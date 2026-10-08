using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using MQTTnet.Adapter;
using MQTTnet.Channel;
using MQTTnet.Diagnostics.Logger;
using MQTTnet.Formatter;
using MQTTnet.Implementations;
using MQTTnet.Server;
using Serilog;

namespace Meshtastic.Mqtt;

/// <summary>
/// Plain-TCP listener for MQTTnet that refuses oversized packets before MQTTnet allocates them.
/// </summary>
/// <remarks>
/// MQTTnet 5.2 reads the fixed header and then does <c>new byte[RemainingLength]</c> (up to 256 MB) before the
/// body arrives and before any hook runs, so a few unauthenticated sockets sending <c>10 FF FF FF 7F</c> can
/// exhaust memory. MQTTnet has no server-side size option, so this adapter replaces its stock TCP adapter with
/// the same plumbing (socket, <see cref="MqttTcpChannel"/>, <see cref="MqttChannelAdapter"/>) plus a channel
/// decorator that watches the byte stream and ends the connection as soon as a declared length exceeds the
/// limit. The adapter only serves the plain endpoint; TLS is not offered by this broker.
/// </remarks>
public sealed class PacketSizeLimitedTcpAdapter(IPAddress bindAddress, int maxPacketSize, ILogger log) : IMqttServerAdapter
{
    Socket? _listener;
    CancellationTokenSource? _cts;
    MqttServerOptions? _options;
    IMqttNetLogger? _mqttLogger;

    public Func<IMqttChannelAdapter, Task>? ClientHandler { get; set; }

    /// <summary>The port actually bound (useful when the configured port is 0).</summary>
    public int BoundPort { get; private set; }

    public Task StartAsync(MqttServerOptions options, IMqttNetLogger logger)
    {
        if (_cts is not null)
            throw new InvalidOperationException("The adapter is already started.");
        _options = options;
        _mqttLogger = logger;
        var endpoint = options.DefaultEndpointOptions;

        var socket = new Socket(bindAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            if (bindAddress.AddressFamily == AddressFamily.InterNetworkV6)
                socket.DualMode = false;   // "::" means IPv6 only, as with MQTTnet's own listener
            if (endpoint.ReuseAddress)
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.NoDelay = endpoint.NoDelay;
            if (endpoint.LingerState is not null)
                socket.LingerState = endpoint.LingerState;
            socket.Bind(new IPEndPoint(bindAddress, endpoint.Port));
            socket.Listen(endpoint.ConnectionBacklog);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        _listener = socket;
        BoundPort = ((IPEndPoint)socket.LocalEndPoint!).Port;
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _ = Task.Run(() => AcceptLoopAsync(socket, token), token);
        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        Cleanup();
        return Task.CompletedTask;
    }

    public void Dispose() => Cleanup();

    void Cleanup()
    {
        try
        {
            _cts?.Cancel();
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
            _listener?.Dispose();
            _listener = null;
        }
    }

    async Task AcceptLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionAborted or SocketError.ConnectionReset
                                                 or SocketError.OperationAborted or SocketError.Interrupted)
            {
                if (cancellationToken.IsCancellationRequested)
                    return;
                continue;
            }
            catch (Exception ex)
            {
                log.Error("Error accepting a TCP connection: {Error}", ex.GetType().Name);
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                continue;
            }
            _ = Task.Run(() => HandleClientAsync(client), CancellationToken.None);
        }
    }

    async Task HandleClientAsync(Socket client)
    {
        NetworkStream? stream = null;
        try
        {
            var options = _options!;
            client.NoDelay = options.DefaultEndpointOptions.NoDelay;
            var remote = client.RemoteEndPoint;
            var local = client.LocalEndPoint;
            stream = new NetworkStream(client, ownsSocket: true);

            var handler = ClientHandler;
            if (handler is null)
                return;

            var channel = new PacketSizeGuardChannel(new MqttTcpChannel(stream, local, remote, null), maxPacketSize,
                declared => log.Warning("Connection closed: packet length {Length} exceeds limits.max_packet_size {MaxPacketSize} from {RemoteIp}",
                    declared, maxPacketSize, (remote as IPEndPoint)?.Address.ToString() ?? "unknown"));
            var formatter = new MqttPacketFormatterAdapter(new MqttBufferWriter(options.WriterBufferSize, options.WriterBufferSizeMax));
            using var adapter = new MqttChannelAdapter(channel, formatter, _mqttLogger!);
            adapter.AllowPacketFragmentation = options.DefaultEndpointOptions.AllowPacketFragmentation;
            await handler(adapter).ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
        catch (IOException)
        {
        }
        catch (Exception ex)
        {
            log.Error("Error handling a TCP connection: {Error}", ex.GetType().Name);
        }
        finally
        {
            try
            {
                if (stream is not null)
                    await stream.DisposeAsync().ConfigureAwait(false);
                client.Dispose();
            }
            catch (Exception ex)
            {
                log.Error("Error closing a TCP connection: {Error}", ex.GetType().Name);
            }
        }
    }
}

/// <summary>
/// Follows the MQTT framing on the read side of a channel and reports end of stream as soon as a packet declares a
/// Remaining Length above the limit (or a malformed length), before the caller can allocate the body.
/// </summary>
/// <remarks>
/// The check runs on the bytes as they arrive, so it does not depend on how the caller splits its reads.
/// A declared length is rejected as soon as its partial value passes the limit, without waiting for the
/// remaining length bytes. Once tripped, every later read returns 0 (connection closed).
/// </remarks>
public sealed class PacketSizeGuardChannel(IMqttChannel inner, int maxPacketSize, Action<long>? onOversized = null) : IMqttChannel
{
    enum State { FixedHeader, RemainingLength, Body }

    State _state = State.FixedHeader;
    long _length;
    long _multiplier;
    int _lengthBytes;
    long _bodyLeft;
    bool _tripped;

    public X509Certificate2 ClientCertificate => inner.ClientCertificate;
    public EndPoint RemoteEndPoint => inner.RemoteEndPoint;
    public EndPoint LocalEndPoint => inner.LocalEndPoint;
    public bool IsSecureConnection => inner.IsSecureConnection;

    public Task ConnectAsync(CancellationToken cancellationToken) => inner.ConnectAsync(cancellationToken);

    public Task DisconnectAsync(CancellationToken cancellationToken) => inner.DisconnectAsync(cancellationToken);

    public Task WriteAsync(ReadOnlySequence<byte> buffer, bool isEndOfPacket, CancellationToken cancellationToken) =>
        inner.WriteAsync(buffer, isEndOfPacket, cancellationToken);

    public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        if (_tripped)
            return 0;
        var read = await inner.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        if (read > 0 && !Accept(buffer.AsSpan(offset, read)))
        {
            _tripped = true;
            onOversized?.Invoke(_length);
            return 0;
        }
        return read;
    }

    /// <summary>Advances the framing state over <paramref name="data"/>; false if a packet breaks the limit.</summary>
    internal bool Accept(ReadOnlySpan<byte> data)
    {
        var i = 0;
        while (i < data.Length)
        {
            switch (_state)
            {
                case State.FixedHeader:
                    i++;
                    _state = State.RemainingLength;
                    _length = 0;
                    _multiplier = 1;
                    _lengthBytes = 0;
                    break;

                case State.RemainingLength:
                    var b = data[i++];
                    _lengthBytes++;
                    _length += (b & 0x7F) * _multiplier;
                    _multiplier *= 128;
                    if (_length > maxPacketSize)
                        return false;
                    if ((b & 0x80) == 0)
                    {
                        _bodyLeft = _length;
                        _state = _length == 0 ? State.FixedHeader : State.Body;
                    }
                    else if (_lengthBytes == 4)
                    {
                        return false;   // more than 4 length bytes: malformed, MQTTnet would refuse it too
                    }
                    break;

                case State.Body:
                    var take = (int)Math.Min(_bodyLeft, data.Length - i);
                    i += take;
                    _bodyLeft -= take;
                    if (_bodyLeft == 0)
                        _state = State.FixedHeader;
                    break;
            }
        }
        return true;
    }

    public void Dispose() => inner.Dispose();
}

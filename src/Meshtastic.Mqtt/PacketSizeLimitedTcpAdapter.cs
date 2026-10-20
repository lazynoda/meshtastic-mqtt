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
/// <para>
/// The adapter is also where the per-IP limits live (see <see cref="ConnectionGuard"/>): they are applied when
/// the connection is accepted, before a single MQTT byte is read, so a flood of sockets or of CONNECTs is cut
/// before it reaches the broker. The bans of an address (see <see cref="AuthBanManager"/>) are applied in the
/// same place, before the connection takes a slot or a token of those limits.
/// </para>
/// </remarks>
public sealed class PacketSizeLimitedTcpAdapter(IPAddress bindAddress, int maxPacketSize, ILogger log,
    ConnectionGuard? guard = null, DropCounters? drops = null, AuthBanManager? bans = null) : IMqttServerAdapter
{
    Socket? _listener;
    CancellationTokenSource? _cts;
    MqttServerOptions? _options;
    IMqttNetLogger? _mqttLogger;

    /// <summary>The per-IP limits applied on accept (never null).</summary>
    internal ConnectionGuard Guard { get; } = guard ?? new ConnectionGuard(new LimitsConfig(), TimeProvider.System);

    /// <summary>The bans applied on accept (null = no bans).</summary>
    internal AuthBanManager? Bans { get; } = bans;

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

            // The per-IP limits, before a single MQTT byte is read. A refused connection is closed at once.
            // The address is unknown when the endpoint is not an IP one: an unknown address is never
            // matched against a ban and is never counted (there is no key to key it by).
            var address = RemoteIp(client.RemoteEndPoint);
            if (address is null)
                log.Debug("Connection from {RemoteEndPoint}: the address is unknown, the bans do not apply", client.RemoteEndPoint);

            // A banned address is closed at once, before it takes a slot or a token of the per-IP limits:
            // the ban is cheaper than the limits, and a banned address has nothing to say.
            if (IsBannedAddress(address))
            {
                drops?.Increment(AuthBanManager.BannedIpReason);
                // Debug per connection: a banned address may keep trying, and a Warning per attempt
                // would flood the log. The refusals are counted in the same summary as the dropped publishes.
                log.Debug("Connection refused from {RemoteIp}: {Reason}", address, AuthBanManager.BannedIpReason);
                CloseRefused(client);
                continue;
            }

            // The per-IP limits are keyed by the address, as always: an unknown one shares the
            // "unknown" key, so it is still bound by the connection cap and the connect rate.
            var remoteIp = address ?? "unknown";
            if (!Guard.TryAcquire(remoteIp, out var refusal))
            {
                drops?.Increment(refusal!);
                // Debug per refusal: an address that floods must not be able to flood the log. The refusals
                // are counted in the same summary as the dropped publishes.
                log.Debug("Connection refused from {RemoteIp}: {Reason}", remoteIp, refusal);
                CloseRefused(client);
                continue;
            }

            try
            {
                _ = Task.Run(() => HandleClientAsync(client, remoteIp), CancellationToken.None);
            }
            catch (Exception ex)
            {
                // The handler never started: give the slot back, or the counter would leak.
                Guard.Release(remoteIp);
                client.Dispose();
                log.Error("Error starting a TCP connection handler: {Error}", ex.GetType().Name);
            }
        }
    }

    /// <summary>
    /// The address of a remote endpoint, or null when it is not an IP one. An unknown address is never
    /// matched against a ban and no failure is ever counted for it: there is no key to key it by.
    /// </summary>
    internal static string? RemoteIp(EndPoint? endpoint) => (endpoint as IPEndPoint)?.Address.ToString();

    /// <summary>
    /// Whether the address must be refused because it is banned. An unknown address (null) never
    /// matches a ban: the bans are keyed by address.
    /// </summary>
    internal bool IsBannedAddress(string? ip) => ip is not null && Bans is not null && Bans.IsBanned(ip);

    /// <summary>Closes a connection the broker refuses at the accept, without a byte of MQTT read.</summary>
    void CloseRefused(Socket client)
    {
        try
        {
            // A clean close, so the client sees the end of the stream instead of a reset.
            client.Shutdown(SocketShutdown.Send);
        }
        catch (Exception ex)
        {
            log.Debug("Error closing a refused TCP connection: {Error}", ex.GetType().Name);
        }
        try
        {
            client.Dispose();
        }
        catch (Exception ex)
        {
            log.Error("Error closing a refused TCP connection: {Error}", ex.GetType().Name);
        }
    }

    async Task HandleClientAsync(Socket client, string remoteIp)
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

            var remoteIpLocal = (remote as IPEndPoint)?.Address.ToString() ?? "unknown";
            var channel = new PacketSizeGuardChannel(new MqttTcpChannel(stream, local, remote, null), maxPacketSize, (reason, declared) =>
            {
                if (reason == PacketSizeGuardChannel.TripReason.Oversized)
                {
                    log.Warning("Connection closed: packet length {Length} exceeds limits.max_packet_size {MaxPacketSize} from {RemoteIp}",
                        declared, maxPacketSize, remoteIpLocal);
                }
                else
                {
                    // The partial value is meaningless here (more than 4 length bytes), so it is not logged.
                    log.Warning("Connection closed: malformed Remaining Length (more than 4 bytes) from {RemoteIp}", remoteIpLocal);
                }
            });
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
            // The per-IP slot is given back on every close path, so the counter never leaks.
            Guard.Release(remoteIp);
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
public sealed class PacketSizeGuardChannel(IMqttChannel inner, int maxPacketSize, Action<PacketSizeGuardChannel.TripReason, long>? onTripped = null) : IMqttChannel
{
    /// <summary>Why the guard ended a connection.</summary>
    public enum TripReason
    {
        /// <summary>The declared Remaining Length (possibly still partial) exceeds the limit; the value is reported.</summary>
        Oversized,
        /// <summary>More than four Remaining Length bytes: the value is meaningless and MQTTnet would refuse it too.</summary>
        Malformed,
    }

    enum State { FixedHeader, RemainingLength, Body }

    State _state = State.FixedHeader;
    long _length;
    long _multiplier;
    int _lengthBytes;
    long _bodyLeft;
    bool _tripped;

    /// <summary>Set by <see cref="Accept"/> when it returns false.</summary>
    internal TripReason? LastTrip { get; private set; }

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
            onTripped?.Invoke(LastTrip ?? TripReason.Oversized, _length);
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
                    {
                        LastTrip = TripReason.Oversized;
                        return false;
                    }
                    if ((b & 0x80) == 0)
                    {
                        _bodyLeft = _length;
                        _state = _length == 0 ? State.FixedHeader : State.Body;
                    }
                    else if (_lengthBytes == 4)
                    {
                        LastTrip = TripReason.Malformed;   // a fifth length byte would follow; MQTTnet would refuse it too
                        return false;
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

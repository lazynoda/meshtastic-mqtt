using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Text;
using MQTTnet;
using MQTTnet.Adapter;
using MQTTnet.Formatter;
using MQTTnet.Packets;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// Review finding 2 (round 2): the client-id claim table must be bounded by the sessions in the server plus recent
/// claims, whatever clients do. A same-user CleanSession=false takeover that dies before ClientConnected used to
/// leave an orphan claim; a ClientConnected that ran after its client had already gone used to write one back; and
/// claims for ids that never got a session event used to stay forever.
/// </summary>
[Collection("Isolated")]
public sealed class ClaimTableTests : IAsyncLifetime
{
    readonly int _port = FreePort();
    readonly LogSink _logs = new();
    BrokerServer.Built _built = null!;

    MqttServer Server => _built.Server;
    BrokerHooks Hooks => _built.Hooks;

    public async ValueTask InitializeAsync()
    {
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger();
        _built = TestBroker.CreateBuilt(Config(_port), logger);
        await Server.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await Server.StopAsync();
        Server.Dispose();
    }

    static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A raw MQTT 3.1.1 CONNECT packet (no will, keep-alive 60).</summary>
    static byte[] Connect(string clientId, string user, string password, bool cleanSession)
    {
        var body = new List<byte>();
        void Str(string s)
        {
            var bytes = Encoding.UTF8.GetBytes(s);
            body.Add((byte)(bytes.Length >> 8));
            body.Add((byte)bytes.Length);
            body.AddRange(bytes);
        }
        Str("MQTT");
        body.Add(4);
        body.Add((byte)(0xC0 | (cleanSession ? 0x02 : 0x00)));
        body.Add(0);
        body.Add(60);
        Str(clientId);
        Str(user);
        Str(password);
        var packet = new List<byte> { 0x10 };
        var x = body.Count;
        do
        {
            var b = (byte)(x % 128);
            x /= 128;
            packet.Add(x > 0 ? (byte)(b | 0x80) : b);
        } while (x > 0);
        packet.AddRange(body);
        return [.. packet];
    }

    /// <summary>Sends CONNECT and resets the connection (RST) right away, before CONNACK can be read.</summary>
    async Task ConnectThenRst(string clientId, string user, string password, bool cleanSession)
    {
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await s.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port), Ct);
        await s.SendAsync(Connect(clientId, user, password, cleanSession), SocketFlags.None, Ct);
        s.LingerState = new LingerOption(true, 0);   // close() sends RST instead of FIN
        s.Close();
    }

    async Task<bool> Quiet(int expectedClients) =>
        await WaitUntil(() => Server.GetClientsAsync().Result.Count == expectedClients && Server.GetSessionsAsync().Result.Count == expectedClients);

    [Fact]
    public async Task SameUserTakeover_ThatDiesBeforeConnack_LeavesNoOrphanClaim()
    {
        // The reviewer's repro: meshdev connected with id X; a second socket sends CONNECT(X, CleanSession=false,
        // meshdev) and resets. 30 times, with a fresh id each time so that an orphan claim cannot hide behind
        // the next iteration's overwrite. At the end sessions, clients and claims are all 0.
        for (var i = 0; i < 30; i++)
        {
            // A fresh client per iteration: a taken-over MqttClient reports IsConnected=false before it has finished
            // tearing down, and reconnecting it at that moment throws (a client-side quirk, not what is under test).
            using var client = new MqttClientFactory().CreateMqttClient();
            var id = $"!5ta1e{i:x3}";
            var result = await client.ConnectAsync(ClientOptions(_port, "meshdev", "large4cats", id), Ct);
            Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
            await ConnectThenRst(id, "meshdev", "large4cats", cleanSession: false);
            Assert.True(await WaitUntil(() => !client.IsConnected), $"iteration {i}: the live client was not taken over");
            Assert.True(await Quiet(0), $"iteration {i}: sessions or clients left behind");
        }

        Assert.True(await WaitUntil(() => Hooks.ClaimCount == 0, 3), $"claims={Hooks.ClaimCount} after 30 takeover+RST");
        var sessions = await Server.GetSessionsAsync();
        var clients = await Server.GetClientsAsync();
        TestContext.Current.SendDiagnosticMessage($"claims sessions={sessions.Count} clients={clients.Count} claims={Hooks.ClaimCount}");
        Assert.Empty(sessions);
        Assert.Empty(clients);
    }

    [Fact]
    public async Task InventedIds_ThatNeverConnect_LeaveNoClaims()
    {
        // Through MQTTnet a new id always gets a session, so an RST after CONNECT ends in SessionDeleted with the
        // claim's own token: nothing accumulates. 300 invented ids leave 0 claims.
        for (var i = 0; i < 300; i++)
            await ConnectThenRst($"invented-{i:d4}", "meshdev", "large4cats", cleanSession: true);
        Assert.True(await Quiet(0));
        Assert.True(await WaitUntil(() => Hooks.ClaimCount == 0, 3), $"claims={Hooks.ClaimCount} after 300 invented ids");
    }

    /// <summary>Hooks attached to the running server (so sweeps see its sessions) but driven by hand.</summary>
    BrokerHooks DetachedHooks(TimeSpan lifetime)
    {
        var hooks = new BrokerHooks(Config(_port), new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger())
        {
            PendingClaimLifetime = lifetime,
        };
        hooks.UseServerForLookups(Server);   // only the server reference: the real hooks stay the server's event handlers
        return hooks;
    }

    static async Task<Hashtable> Claim(BrokerHooks hooks, string id, string user = "meshdev", string password = "large4cats")
    {
        var items = new Hashtable();
        var args = new ValidatingConnectionEventArgs(new MqttConnectPacket { ClientId = id, Username = user, Password = Encoding.UTF8.GetBytes(password) },
            new FakeAdapter(), items, CancellationToken.None);
        await hooks.ValidateConnectionAsync(args);
        Assert.Equal(MqttConnectReasonCode.Success, args.ReasonCode);
        return items;
    }

    static ClientConnectedEventArgs Connected(string id, IDictionary items, string user = "meshdev") =>
        new(new MqttConnectPacket { ClientId = id, Username = user }, MqttProtocolVersion.V311, new IPEndPoint(IPAddress.Loopback, 40000), items);

    [Fact]
    public async Task PendingClaims_ThatNeverGetASession_AreSweptAfterTheirLifetime()
    {
        // The safety net for any path where a CONNECT passes the hook but no session event ever follows: claims
        // older than PendingClaimLifetime whose id has no session are swept every SweepEveryInserts inserts, so the
        // table is bounded by sessions + claims younger than the lifetime + one sweep interval, whatever ids clients
        // invent. A connected client's claim is never swept while its session exists.
        var hooks = DetachedHooks(TimeSpan.FromMilliseconds(300));
        var live = new MqttClientFactory().CreateMqttClient();
        Assert.Equal(MqttClientConnectResultCode.Success, (await live.ConnectAsync(ClientOptions(_port, "meshdev", "large4cats", "live-node"), Ct)).ResultCode);
        await Claim(hooks, "live-node");   // mirrors the real hooks' claim for the connected client

        const int ids = 500;
        for (var i = 0; i < ids; i++)
            await Claim(hooks, $"invented-{i:d4}");
        var peak = hooks.ClaimCount;
        await Task.Delay(400, Ct);
        for (var i = 0; i < BrokerHooks.SweepEveryInserts; i++)
            await Claim(hooks, $"later-{i:d4}");
        var after = hooks.ClaimCount;
        TestContext.Current.SendDiagnosticMessage($"claims peak={peak} after lifetime + {BrokerHooks.SweepEveryInserts} inserts={after}");

        Assert.True(after <= BrokerHooks.SweepEveryInserts + 1, $"{after} claims left: the first {ids} invented ids were not swept");
        Assert.True(await WaitUntil(() => _logs.Events.Any(e => e.RenderMessage().Contains("Swept"))));
        // The connected client's claim, as old as the swept ones, survived because its session exists.
        Assert.Single(await Server.GetSessionsAsync());
        Assert.True(hooks.HasClaim("live-node"), "the connected client's claim was swept");
        await live.DisconnectAsync(cancellationToken: Ct);
    }

    [Fact]
    public async Task Sweep_AlsoRunsOnTime_NotOnlyOnInsertCount()
    {
        // A trickle of claims (fewer than SweepEveryInserts) must not keep stale ones for ever: after a lifetime
        // without a sweep, the next insert sweeps.
        var hooks = DetachedHooks(TimeSpan.FromMilliseconds(200));
        for (var i = 0; i < 5; i++)
            await Claim(hooks, $"trickle-{i}");
        Assert.Equal(5, hooks.ClaimCount);
        await Task.Delay(300, Ct);
        await Claim(hooks, "trickle-late");
        Assert.Equal(1, hooks.ClaimCount);
    }

    [Fact]
    public async Task LateClientConnected_ForASessionAlreadyGone_LeavesNoClaim()
    {
        // ClientConnected runs after the CONNACK. If the client died in between, MQTTnet has already deleted the
        // session and fired SessionDeleted (which released the claim); a ClientConnected arriving now must not write
        // the claim back, because nothing would ever release it again.
        var hooks = DetachedHooks(TimeSpan.FromSeconds(30));
        var items = await Claim(hooks, "late-1");
        Assert.Equal(1, hooks.ClaimCount);
        await hooks.OnSessionDeletedAsync(new SessionDeletedEventArgs("late-1", "meshdev", items));
        Assert.Equal(0, hooks.ClaimCount);

        await hooks.OnClientConnectedAsync(Connected("late-1", items));   // no session "late-1" in the server
        Assert.Equal(0, hooks.ClaimCount);
    }

    [Fact]
    public async Task LateClientConnected_DoesNotOverwriteANewerConnectedClaim()
    {
        // Same id, two connects of the same user in quick succession (a takeover). The second connect's
        // ClientConnected may run before the first one's. The first, arriving late, must not replace the newer
        // connected claim with its own older token, or the newer session's deletion would never match.
        var hooks = DetachedHooks(TimeSpan.FromSeconds(30));
        var first = await Claim(hooks, "race-1");
        var second = await Claim(hooks, "race-1");

        // The second connect has a live session with its own items. Connect a real client so the server holds it.
        var live = new MqttClientFactory().CreateMqttClient();
        Assert.Equal(MqttClientConnectResultCode.Success, (await live.ConnectAsync(ClientOptions(_port, "meshdev", "large4cats", "race-1"), Ct)).ResultCode);
        var serverItems = (await Server.GetSessionAsync("race-1")).Items;
        var realToken = serverItems[BrokerHooks.ClaimTokenKey];   // the server's own hooks' token, restored below
        foreach (DictionaryEntry e in second)
            serverItems[e.Key] = e.Value;

        await hooks.OnClientConnectedAsync(Connected("race-1", serverItems));   // second connect, current session
        Assert.Equal(1, hooks.ClaimCount);
        await hooks.OnClientConnectedAsync(Connected("race-1", first));         // first connect, late, session replaced
        Assert.Equal(1, hooks.ClaimCount);

        // Deleting the first (replaced) session must not release the newer claim; deleting the second must.
        await hooks.OnSessionDeletedAsync(new SessionDeletedEventArgs("race-1", "meshdev", first));
        Assert.Equal(1, hooks.ClaimCount);
        await hooks.OnSessionDeletedAsync(new SessionDeletedEventArgs("race-1", "meshdev", serverItems));
        Assert.Equal(0, hooks.ClaimCount);
        serverItems[BrokerHooks.ClaimTokenKey] = realToken;
        await live.DisconnectAsync(cancellationToken: Ct);
    }

    [Fact]
    public async Task SessionDeletedForAnotherUser_DoesNotDropAPendingClaim()
    {
        // The same-user rule must not become a cross-user hole: a SessionDeleted whose user is not the claim's
        // owner (and whose token does not match) leaves the pending claim alone.
        var hooks = new BrokerHooks(Config(_port), new LoggerConfiguration().WriteTo.Sink(_logs).CreateLogger());
        var args = new ValidatingConnectionEventArgs(new MqttConnectPacket { ClientId = "pending-1", Username = "alice", Password = Encoding.UTF8.GetBytes(AlicePassword) },
            new FakeAdapter(), new Hashtable(), CancellationToken.None);
        await hooks.ValidateConnectionAsync(args);
        Assert.Equal(MqttConnectReasonCode.Success, args.ReasonCode);
        Assert.Equal(1, hooks.ClaimCount);

        await hooks.OnSessionDeletedAsync(new SessionDeletedEventArgs("pending-1", "meshdev", new Hashtable()));
        Assert.Equal(1, hooks.ClaimCount);

        await hooks.OnSessionDeletedAsync(new SessionDeletedEventArgs("pending-1", "alice", new Hashtable()));
        Assert.Equal(0, hooks.ClaimCount);
    }

    sealed class FakeAdapter : IMqttChannelAdapter
    {
        public long BytesReceived => 0;
        public long BytesSent => 0;
        public System.Security.Cryptography.X509Certificates.X509Certificate2 ClientCertificate => null!;
        public EndPoint RemoteEndPoint { get; } = new IPEndPoint(IPAddress.Parse("203.0.113.7"), 40000);
        public EndPoint LocalEndPoint { get; } = new IPEndPoint(IPAddress.Loopback, 1883);
        public bool IsSecureConnection => false;
        public MqttPacketFormatterAdapter PacketFormatterAdapter { get; } = new(MqttProtocolVersion.V311, new MqttBufferWriter(4096, 65535));
        public Task ConnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DisconnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<MqttPacket> ReceivePacketAsync(CancellationToken cancellationToken) => Task.FromResult<MqttPacket>(null!);
        public void ResetStatistics() { }
        public Task SendPacketAsync(MqttPacket packet, CancellationToken cancellationToken) => Task.CompletedTask;
        public void Dispose() { }
    }
}

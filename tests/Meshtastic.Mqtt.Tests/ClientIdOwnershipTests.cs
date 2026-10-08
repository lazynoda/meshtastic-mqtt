using System.Collections.Concurrent;
using MQTTnet;
using MQTTnet.Formatter;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// A client id belongs to the user whose session holds it (review finding B1). Another user may not take it
/// over, whatever CleanSession says; the same user may, and the id is free again once the session is gone.
/// </summary>
public sealed class ClientIdOwnershipTests : IAsyncLifetime
{
    readonly int _port = FreePort();
    readonly LogSink _logs = new();
    MqttServer _server = null!;

    public async ValueTask InitializeAsync()
    {
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger();
        _server = TestBroker.Create(Config(_port), logger);
        await _server.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _server.StopAsync();
        _server.Dispose();
    }

    static CancellationToken Ct => TestContext.Current.CancellationToken;

    async Task<(IMqttClient Client, MqttClientConnectResult Result, ConcurrentQueue<string> Received)> Connect(
        string user, string password, string clientId, bool cleanSession = true,
        MqttProtocolVersion version = MqttProtocolVersion.V311, uint sessionExpiry = 0, int? port = null)
    {
        var received = new ConcurrentQueue<string>();
        var client = new MqttClientFactory().CreateMqttClient();
        client.ApplicationMessageReceivedAsync += e =>
        {
            received.Enqueue(e.ApplicationMessage.Topic);
            return Task.CompletedTask;
        };
        var result = await client.ConnectAsync(ClientOptions(port ?? _port, user, password, clientId, version, cleanSession, sessionExpiry), Ct);
        return (client, result, received);
    }

    static async Task<MqttClientSubscribeResultCode> Subscribe(IMqttClient client, string filter)
    {
        var result = await client.SubscribeAsync(new MqttClientSubscribeOptionsBuilder().WithTopicFilter(filter).Build(), Ct);
        return Assert.Single(result.Items).ResultCode;
    }

    async Task PublishTestPacket(int? port = null)
    {
        var (pub, result, _) = await Connect("meshdev", "large4cats", "!0badc0de", port: port);
        Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
        await pub.PublishAsync(new MqttApplicationMessageBuilder().WithTopic("msh/ES/2/e/Test/!1a2b3c4d")
            .WithPayload(PublishFilterTests.Fixture("test_ag.bin"))
            .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce).Build(), Ct);
        await pub.DisconnectAsync(cancellationToken: Ct);
    }

    [Fact]
    public async Task CrossUserTakeover_WithoutCleanSession_IsRefused_AndTheVictimKeepsReceiving()
    {
        // The reviewer's repro: alice holds a session with a downlink subscription; meshdev (public
        // credentials) reconnects with the same client id and CleanSession=false to inherit it.
        var (alice, aliceResult, aliceGot) = await Connect("alice", AlicePassword, "dash-victim");
        Assert.Equal(MqttClientConnectResultCode.Success, aliceResult.ResultCode);
        Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, await Subscribe(alice, "msh/ES/2/e/Test/#"));

        var (attacker, attackResult, attackerGot) = await Connect("meshdev", "large4cats", "dash-victim", cleanSession: false);
        Assert.Equal(MqttClientConnectResultCode.ClientIdentifierNotValid, attackResult.ResultCode);
        Assert.False(attacker.IsConnected);

        await Task.Delay(300, Ct);
        Assert.True(alice.IsConnected);

        await PublishTestPacket();
        Assert.True(await WaitUntil(() => !aliceGot.IsEmpty), "alice must keep receiving after the refused takeover");
        Assert.Empty(attackerGot);
        Assert.Contains(_logs.Events, e => e.RenderMessage().Contains("belongs to a session of another user"));
    }

    [Fact]
    public async Task CrossUserTakeover_WithCleanSession_IsRefused()
    {
        var (alice, _, _) = await Connect("alice", AlicePassword, "dash-2");
        Assert.True(alice.IsConnected);

        var (_, result, _) = await Connect("meshdev", "large4cats", "dash-2", cleanSession: true);
        Assert.Equal(MqttClientConnectResultCode.ClientIdentifierNotValid, result.ResultCode);

        await Task.Delay(300, Ct);
        Assert.True(alice.IsConnected, "a refused CONNECT must not kick the session owner");
    }

    [Fact]
    public async Task CrossUserTakeover_IsRefusedOnMqtt5Too()
    {
        var (alice, _, _) = await Connect("alice", AlicePassword, "dash-3", version: MqttProtocolVersion.V500);
        Assert.True(alice.IsConnected);

        var (_, result, _) = await Connect("meshdev", "large4cats", "dash-3", cleanSession: false, version: MqttProtocolVersion.V500);
        Assert.Equal(MqttClientConnectResultCode.ClientIdentifierNotValid, result.ResultCode);
        Assert.True(alice.IsConnected);
    }

    [Fact]
    public async Task SameUserTakeover_StillWorks_AndKeepsTheSession()
    {
        var (first, _, _) = await Connect("alice", AlicePassword, "dash-4");
        Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, await Subscribe(first, "msh/ES/2/e/Test/#"));

        var (second, result, secondGot) = await Connect("alice", AlicePassword, "dash-4", cleanSession: false);
        Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
        Assert.True(result.IsSessionPresent);
        Assert.True(await WaitUntil(() => !first.IsConnected));

        // The reused session still carries alice's subscription: no SUBSCRIBE needed.
        await PublishTestPacket();
        Assert.True(await WaitUntil(() => !secondGot.IsEmpty));
    }

    [Fact]
    public async Task ClientIdOfAClosedSession_IsFreeForAnotherUser()
    {
        var (alice, _, _) = await Connect("alice", AlicePassword, "dash-5");
        await alice.DisconnectAsync(cancellationToken: Ct);
        Assert.True(await WaitUntil(() => _server.GetClientsAsync().Result.All(c => c.Id != "dash-5")));

        var (_, result, _) = await Connect("meshdev", "large4cats", "dash-5");
        Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
    }

    [Fact]
    public async Task PersistedSessionOfAnotherUser_IsRefused_UntilItExpires()
    {
        // A broker with persistent sessions: alice's session outlives her connection for 2 s.
        var port = FreePort();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger();
        var server = TestBroker.Create(Config(port), logger, persistentSessions: true);
        await server.StartAsync();
        try
        {
            var (alice, _, _) = await Connect("alice", AlicePassword, "dash-6", cleanSession: false,
                version: MqttProtocolVersion.V500, sessionExpiry: 2, port: port);
            Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, await Subscribe(alice, "msh/ES/2/e/Test/#"));
            await alice.DisconnectAsync(cancellationToken: Ct);
            Assert.True(await WaitUntil(() => server.GetClientsAsync().Result.All(c => c.Id != "dash-6")));
            Assert.Contains(await server.GetSessionsAsync(), s => s.Id == "dash-6");

            var (attacker, refused, attackerGot) = await Connect("meshdev", "large4cats", "dash-6", cleanSession: false,
                version: MqttProtocolVersion.V500, port: port);
            Assert.Equal(MqttClientConnectResultCode.ClientIdentifierNotValid, refused.ResultCode);
            Assert.False(attacker.IsConnected);

            // Once the session has expired the id is free: no stale ownership locks it out.
            await Task.Delay(TimeSpan.FromSeconds(3), Ct);
            var (meshdev, accepted, _) = await Connect("meshdev", "large4cats", "dash-6", cleanSession: false,
                version: MqttProtocolVersion.V500, port: port);
            Assert.Equal(MqttClientConnectResultCode.Success, accepted.ResultCode);
            Assert.False(accepted.IsSessionPresent);
            Assert.Equal(MqttClientSubscribeResultCode.NotAuthorized, await Subscribe(meshdev, "msh/ES/2/e/Test/#"));
            Assert.Empty(attackerGot);
        }
        finally
        {
            await server.StopAsync();
            server.Dispose();
        }
    }
}

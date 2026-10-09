using System.Diagnostics;
using MQTTnet;
using MQTTnet.Server;
using Serilog;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// Review finding M1: the password-hashing queue must not let a flood of bad logins hold good ones hostage,
/// and a cold reconnect storm of meshdev must pay PBKDF2 once, not once per node. One KDF slot, as on the
/// 2-vCPU VM.
/// </summary>
[Collection("Isolated")]
public sealed class AuthQueueTests : IAsyncLifetime
{
    readonly int _port = FreePort();
    readonly LogSink _logs = new();
    MqttServer _server = null!;

    public async ValueTask InitializeAsync()
    {
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger();
        _server = TestBroker.Create(Config(_port), logger, maxConcurrentKdf: 1);
        await _server.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _server.StopAsync();
        _server.Dispose();
    }

    static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Time of one meshdev PBKDF2 (600k iterations) on this machine, after a warm-up.</summary>
    static double SingleKdfMs()
    {
        Assert.True(PasswordHasher.TryParse(AuthTests.MeshdevHash, out var hash, out _));
        hash!.Verify("warm-up"u8);
        var watch = Stopwatch.StartNew();
        hash.Verify("large4cats"u8);
        return watch.Elapsed.TotalMilliseconds;
    }

    async Task<(MqttClientConnectResult Result, double Ms)> TimedConnect(string user, string password, string clientId)
    {
        using var client = new MqttClientFactory().CreateMqttClient();
        var watch = Stopwatch.StartNew();
        var result = await client.ConnectAsync(ClientOptions(_port, user, password, clientId), Ct);
        return (result, watch.Elapsed.TotalMilliseconds);
    }

    [Fact]
    public async Task ColdLegitLogin_DuringUnknownUserFlood_IsNotStarved()
    {
        // The reviewer's repro: 20 logins with made-up usernames queued in front of a cold meshdev login.
        var single = SingleKdfMs();
        var flood = Enumerable.Range(0, 20)
            .Select(i => TimedConnect($"mallory{i}", "large4cats", $"flood-{i}"))
            .ToArray();
        await Task.Delay(150, Ct);

        var (legit, legitMs) = await TimedConnect("meshdev", "large4cats", "!c01d0001");
        var bound = Math.Max(1500, 4 * single);
        TestContext.Current.SendDiagnosticMessage($"M1 single={single:F0}ms legit={legitMs:F0}ms bound={bound:F0}ms (20 unknown-user logins queued, 1 slot)");
        Assert.Equal(MqttClientConnectResultCode.Success, legit.ResultCode);
        Assert.True(legitMs < bound, $"cold legitimate login took {legitMs:F0} ms (bound {bound:F0} ms, one KDF = {single:F0} ms)");

        foreach (var (result, _) in await Task.WhenAll(flood))
            Assert.NotEqual(MqttClientConnectResultCode.Success, result.ResultCode);
    }

    [Fact]
    public async Task ColdLegitStorm_DuringWrongPasswordFlood_IsServedFirst()
    {
        // 3 different wrong passwords for meshdev (same lane and same username as the real nodes, within the
        // per-user cap) are queued, then 10 nodes reconnect with the real password. They share one check, which
        // has the most waiters and runs next.
        var single = SingleKdfMs();
        var flood = Enumerable.Range(0, 3)
            .Select(i => TimedConnect("meshdev", $"guess-{i}", $"flood-{i}"))
            .ToArray();
        await Task.Delay(150, Ct);

        var watch = Stopwatch.StartNew();
        var nodes = await Task.WhenAll(Enumerable.Range(0, 10).Select(i => TimedConnect("meshdev", "large4cats", $"!5702{i:x4}")));
        var stormMs = watch.Elapsed.TotalMilliseconds;
        var bound = Math.Max(1500, 4 * single);
        TestContext.Current.SendDiagnosticMessage($"M1 storm-vs-flood single={single:F0}ms storm={stormMs:F0}ms bound={bound:F0}ms (3 wrong-password meshdev logins queued, 10 real nodes, 1 slot)");
        Assert.All(nodes, r => Assert.Equal(MqttClientConnectResultCode.Success, r.Result.ResultCode));
        Assert.True(stormMs < bound, $"10 real nodes took {stormMs:F0} ms behind 3 queued guesses (bound {bound:F0} ms)");

        foreach (var (result, _) in await Task.WhenAll(flood))
            Assert.NotEqual(MqttClientConnectResultCode.Success, result.ResultCode);
    }

    [Fact]
    public async Task ColdLogins_UnderTwoWaiterGuessFlood_ForMeshdev_AreServed()
    {
        // Review finding 1 (round 2), the reviewer's flood: 8 attackers send each wrong meshdev password twice
        // (2 waiters per check) in a loop, 1 slot. The per-user cap keeps meshdev to 4 pending checks (the rest
        // are Busy at once) and usernames are served round-robin, so a cold alice waits for at most the check
        // that is running plus one meshdev check: deterministic, asserted tightly.
        // A cold meshdev reconnect storm (10 nodes with the real password, retrying on Busy as firmware does)
        // competes with the flood for meshdev's own 4 places: nothing tells a real node from a guess before PBKDF2
        // runs, so getting a place is a race the node wins within a few rounds. Once one node is in, the others
        // join its check for free and it has the most waiters, so it runs next. Asserted: every node succeeds, the
        // attempt that gets in is served well below the queue timeout, and the whole storm settles within seconds.
        var single = SingleKdfMs();
        using var stop = new CancellationTokenSource();
        var floodSuccesses = 0;
        var floodAttempts = 0;
        var flood = Enumerable.Range(0, 8).Select(t => Task.Run(async () =>
        {
            for (var i = 0; !stop.IsCancellationRequested; i++)
            {
                var password = $"guess-{t}-{i}";
                var results = await Task.WhenAll(TimedConnect("meshdev", password, $"flood-{t}-a"), TimedConnect("meshdev", password, $"flood-{t}-b"));
                Interlocked.Add(ref floodAttempts, 2);
                if (results.Any(r => r.Result.ResultCode == MqttClientConnectResultCode.Success))
                    Interlocked.Increment(ref floodSuccesses);
            }
        })).ToArray();
        await Task.Delay(300, Ct);

        var (alice, aliceMs) = await TimedConnect("alice", AlicePassword, "dash-cold");
        var aliceBound = Math.Max(1500, 3 * single);
        TestContext.Current.SendDiagnosticMessage($"M1r2 alice: single={single:F0}ms alice={aliceMs:F0}ms bound={aliceBound:F0}ms result={alice.ResultCode}");
        Assert.Equal(MqttClientConnectResultCode.Success, alice.ResultCode);
        Assert.True(aliceMs < aliceBound, $"cold alice took {aliceMs:F0} ms under the meshdev flood (bound {aliceBound:F0} ms)");

        var watch = Stopwatch.StartNew();
        var storm = await Task.WhenAll(Enumerable.Range(0, 10).Select(async i =>
        {
            var busy = 0;
            while (true)
            {
                var (result, ms) = await TimedConnect("meshdev", "large4cats", $"!c01d{i:x4}");
                if (result.ResultCode != MqttClientConnectResultCode.ServerUnavailable || watch.ElapsedMilliseconds > 10_000)
                    return (result, busy, ms);
                busy++;
                await Task.Delay(1, Ct);
            }
        }));
        var stormMs = watch.Elapsed.TotalMilliseconds;
        var attemptBound = Math.Max(1500, 4 * single);
        const double stormBound = 6000;
        stop.Cancel();
        await Task.WhenAll(flood);
        TestContext.Current.SendDiagnosticMessage($"M1r2 storm: storm={stormMs:F0}ms bound={stormBound:F0}ms admittedAttempt max={storm.Max(s => s.ms):F0}ms bound={attemptBound:F0}ms "
            + $"busyRetries={storm.Sum(s => s.busy)} floodAttempts={floodAttempts} floodSuccesses={floodSuccesses}");
        Assert.All(storm, s => Assert.Equal(MqttClientConnectResultCode.Success, s.result.ResultCode));
        Assert.All(storm, s => Assert.True(s.ms < attemptBound, $"an admitted cold meshdev login took {s.ms:F0} ms (bound {attemptBound:F0} ms)"));
        Assert.True(stormMs < stormBound, $"10 cold meshdev nodes took {stormMs:F0} ms to get in under the flood (bound {stormBound:F0} ms)");
        Assert.Equal(0, floodSuccesses);
    }

    [Fact]
    public async Task ColdReconnectStorm_OfOneUser_PaysTheKdfAboutOnce()
    {
        // 16 meshdev nodes reconnect at once after a broker restart: one PBKDF2, not 16 in series.
        var single = SingleKdfMs();
        var watch = Stopwatch.StartNew();
        var results = await Task.WhenAll(Enumerable.Range(0, 16)
            .Select(i => TimedConnect("meshdev", "large4cats", $"!5701{i:x4}")));
        var totalMs = watch.Elapsed.TotalMilliseconds;
        var bound = 3 * single + 1000;
        TestContext.Current.SendDiagnosticMessage($"M1 storm single={single:F0}ms total={totalMs:F0}ms bound={bound:F0}ms (16 cold meshdev logins, 1 slot)");
        Assert.All(results, r => Assert.Equal(MqttClientConnectResultCode.Success, r.Result.ResultCode));
        Assert.True(totalMs < bound, $"16 concurrent cold logins took {totalMs:F0} ms (bound {bound:F0} ms, one KDF = {single:F0} ms)");
    }
}

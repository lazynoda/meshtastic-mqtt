using System.Collections;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Meshtastic.Mqtt;
using MQTTnet;
using MQTTnet.Adapter;
using MQTTnet.Formatter;
using MQTTnet.Packets;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The auth bans of phase 4: the failed logins per IP address, the window they are counted in, the ban
/// they cause, the addresses that are exempt and the bounded tables behind them.
/// </summary>
/// <remarks>
/// The clock is a fake one, so the window and the ban are tested without a single sleep.
/// </remarks>
public sealed class AuthBanTests
{
    // A 100k-iteration hash (the cheapest the broker accepts): the tests below check several passwords
    // and a slow hash would make them crawl.
    const string FastHash = AuthTests.AliceHash;

    static BrokerConfig Config(string limits = "", bool withAlice = false)
    {
        var yaml = $"users:\n  - username: meshdev\n    password_hash: \"{FastHash}\"\n";
        if (withAlice)
            yaml += $"  - username: alice\n    password_hash: \"{FastHash}\"\n";
        yaml += limits + "\n";
        return ConfigLoader.Parse(yaml);
    }

    static LimitsConfig Limits(string limits) => Config(limits).Limits!;

    /// <summary>A ban manager, a fake clock and the log it writes to.</summary>
    static (AuthBanManager Bans, FakeClock Clock, LogSink Logs) Manager(string limits = "")
    {
        var clock = new FakeClock();
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();
        return (new AuthBanManager(Limits(limits), clock, logger), clock, logs);
    }

    static byte[] Pw(string s) => Encoding.UTF8.GetBytes(s);

    // ---- The configuration ----------------------------------------------------------------------------------

    [Fact]
    public void TheAuthBanKeys_HaveTheirDefaults()
    {
        var limits = Config().Limits!;
        Assert.Equal(10, limits.AuthFailMaxPerIp);
        Assert.Equal(600, limits.AuthFailWindowSeconds);
        Assert.Equal(3600, limits.AuthBanSeconds);
        Assert.Empty(limits.AuthBanExempt!);
    }

    [Fact]
    public void TheAuthBanKeys_CanBeSet()
    {
        var limits = Limits("""
            limits:
              auth_fail_max_per_ip: 3
              auth_fail_window_seconds: 30
              auth_ban_seconds: 120
              auth_ban_exempt: ['10.0.0.0/8', '2001:db8::/32']
            """);
        Assert.Equal(3, limits.AuthFailMaxPerIp);
        Assert.Equal(30, limits.AuthFailWindowSeconds);
        Assert.Equal(120, limits.AuthBanSeconds);
        Assert.Equal(["10.0.0.0/8", "2001:db8::/32"], limits.AuthBanExempt!);
    }

    [Fact]
    public void ZeroFailures_TurnsTheBansOff()
    {
        var limits = Limits("limits:\n  auth_fail_max_per_ip: 0");
        Assert.Equal(0, limits.AuthFailMaxPerIp);

        var (bans, _, logs) = Manager("limits:\n  auth_fail_max_per_ip: 0");
        Assert.False(bans.Enabled);
        for (var i = 0; i < 50; i++)
            Assert.False(bans.RecordFailure("1.2.3.4"));
        Assert.False(bans.IsBanned("1.2.3.4"));
        Assert.Equal(0, bans.FailuresFor("1.2.3.4"));
        Assert.Empty(logs.Events);
    }

    [Theory]
    [InlineData("limits:\n  auth_fail_max_per_ip: -1", "limits.auth_fail_max_per_ip")]
    [InlineData("limits:\n  auth_fail_max_per_ip: 100001", "limits.auth_fail_max_per_ip")]
    [InlineData("limits:\n  auth_fail_max_per_ip:", "limits.auth_fail_max_per_ip")]
    [InlineData("limits:\n  auth_fail_window_seconds: 9", "limits.auth_fail_window_seconds")]
    [InlineData("limits:\n  auth_fail_window_seconds: 86401", "limits.auth_fail_window_seconds")]
    [InlineData("limits:\n  auth_fail_window_seconds:", "limits.auth_fail_window_seconds")]
    [InlineData("limits:\n  auth_ban_seconds: 59", "limits.auth_ban_seconds")]
    [InlineData("limits:\n  auth_ban_seconds: 604801", "limits.auth_ban_seconds")]
    [InlineData("limits:\n  auth_ban_seconds:", "limits.auth_ban_seconds")]
    [InlineData("limits:\n  auth_ban_exempt: ['10.0.0.0/33']", "limits.auth_ban_exempt")]
    [InlineData("limits:\n  auth_ban_exempt: ['2001:db8::/129']", "limits.auth_ban_exempt")]
    [InlineData("limits:\n  auth_ban_exempt: ['not-an-ip']", "limits.auth_ban_exempt")]
    [InlineData("limits:\n  auth_ban_exempt: ['10.0.0.0/8', 'nonsense']", "limits.auth_ban_exempt")]
    public void InvalidAuthBanValues_AreRejected(string extra, string mentions)
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(
            $"users:\n  - username: meshdev\n    password_hash: \"{FastHash}\"\n{extra}\n"));
        Assert.Contains(mentions, ex.Message);
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.1.2.3", true)]
    [InlineData("10.0.0.0/8", "11.1.2.3", false)]
    [InlineData("10.0.0.0/8", "::ffff:10.1.2.3", true)]        // an IPv4-mapped IPv6 address is an IPv4 one
    [InlineData("10.0.0.0/8", "::ffff:11.1.2.3", false)]
    [InlineData("192.168.1.0/24", "192.168.1.255", true)]
    [InlineData("192.168.1.0/24", "192.168.2.1", false)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    [InlineData("2001:db8::/32", "2001:db8::1", true)]
    [InlineData("2001:db8::/32", "2001:db9::1", false)]
    [InlineData("2001:db8::/32", "10.1.2.3", false)]
    [InlineData("10.0.0.0/8", "2001:db8::1", false)]
    public void TheCidrMatcher_TakesTheAddressApart(string range, string address, bool expected)
    {
        Assert.True(IpCidr.TryParse(range, out var cidr, out var error), error);
        Assert.Equal(expected, cidr!.Matches(address));
    }

    // ---- Counting ------------------------------------------------------------------------------------------

    [Fact]
    public void TheNthFailure_BansTheAddress_AndClearsItsCounter()
    {
        var (bans, _, logs) = Manager("limits:\n  auth_fail_max_per_ip: 3");

        Assert.False(bans.RecordFailure("1.2.3.4"));
        Assert.False(bans.RecordFailure("1.2.3.4"));
        Assert.False(bans.IsBanned("1.2.3.4"));
        Assert.Equal(2, bans.FailuresFor("1.2.3.4"));

        // The third failure is the limit: the address is banned and its counter is cleared.
        Assert.True(bans.RecordFailure("1.2.3.4"));
        Assert.True(bans.IsBanned("1.2.3.4"));
        Assert.Equal(0, bans.FailuresFor("1.2.3.4"));

        var warning = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);
        Assert.StartsWith("Banned ", warning.MessageTemplate.Text);
        Assert.Contains("1.2.3.4", warning.Properties["RemoteIp"].ToString());
        Assert.Contains("3600", warning.Properties["Seconds"].ToString());
        Assert.Contains("3", warning.Properties["Failures"].ToString());
    }

    [Fact]
    public void AnotherAddress_HasItsOwnCounter()
    {
        var (bans, _, _) = Manager("limits:\n  auth_fail_max_per_ip: 2");
        bans.RecordFailure("1.2.3.4");
        Assert.Equal(1, bans.FailuresFor("1.2.3.4"));
        Assert.Equal(0, bans.FailuresFor("5.6.7.8"));
    }

    [Fact]
    public void TheWindowExpiry_StartsANewWindow()
    {
        var (bans, clock, _) = Manager("limits:\n  auth_fail_max_per_ip: 3\n  auth_fail_window_seconds: 600");
        bans.RecordFailure("1.2.3.4");
        bans.RecordFailure("1.2.3.4");
        Assert.Equal(2, bans.FailuresFor("1.2.3.4"));

        // The window has passed: the next failure starts a new one, so the address is not banned yet.
        clock.Advance(TimeSpan.FromSeconds(601));
        Assert.False(bans.RecordFailure("1.2.3.4"));
        Assert.Equal(1, bans.FailuresFor("1.2.3.4"));
        Assert.False(bans.IsBanned("1.2.3.4"));
    }

    [Fact]
    public void TheBanEnds_AfterTheBanTime()
    {
        var (bans, clock, _) = Manager("limits:\n  auth_fail_max_per_ip: 1\n  auth_ban_seconds: 60");
        Assert.True(bans.RecordFailure("1.2.3.4"));
        Assert.True(bans.IsBanned("1.2.3.4"));

        clock.Advance(TimeSpan.FromSeconds(60));
        Assert.False(bans.IsBanned("1.2.3.4"));

        // The address may be banned again.
        Assert.True(bans.RecordFailure("1.2.3.4"));
        Assert.True(bans.IsBanned("1.2.3.4"));
    }

    [Fact]
    public void OnlyPasswordFailures_Count()
    {
        Assert.True(AuthBanManager.CountsAsFailure(MqttConnectReasonCode.BadUserNameOrPassword));
        Assert.True(AuthBanManager.CountsAsFailure(MqttConnectReasonCode.BadAuthenticationMethod));

        // A full password queue is not a password failure, and neither is a client-id conflict, a banned
        // address or an internal error.
        Assert.False(AuthBanManager.CountsAsFailure(MqttConnectReasonCode.ServerBusy));
        Assert.False(AuthBanManager.CountsAsFailure(MqttConnectReasonCode.ClientIdentifierNotValid));
        Assert.False(AuthBanManager.CountsAsFailure(MqttConnectReasonCode.Banned));
        Assert.False(AuthBanManager.CountsAsFailure(MqttConnectReasonCode.UnspecifiedError));
        Assert.False(AuthBanManager.CountsAsFailure(MqttConnectReasonCode.NotAuthorized));
        Assert.False(AuthBanManager.CountsAsFailure(MqttConnectReasonCode.Success));
    }

    [Fact]
    public void AReasonThatIsNotAPasswordFailure_IsNotCounted()
    {
        var (bans, _, _) = Manager("limits:\n  auth_fail_max_per_ip: 1");
        Assert.False(bans.RecordFailure("1.2.3.4", MqttConnectReasonCode.ServerBusy));
        Assert.False(bans.RecordFailure("1.2.3.4", MqttConnectReasonCode.ClientIdentifierNotValid));
        Assert.False(bans.RecordFailure("1.2.3.4", MqttConnectReasonCode.Banned));
        Assert.Equal(0, bans.FailuresFor("1.2.3.4"));
        Assert.False(bans.IsBanned("1.2.3.4"));
    }

    // ---- The exemptions ------------------------------------------------------------------------------------

    [Fact]
    public void AnExemptAddress_IsNeverCountedNorBanned()
    {
        var (bans, _, _) = Manager("limits:\n  auth_fail_max_per_ip: 2\n  auth_ban_exempt: ['10.0.0.0/8', '2001:db8::/32']");

        // An exempt IPv4 address, an exempt IPv6 address and an IPv4-mapped IPv6 address.
        foreach (var ip in new[] { "10.1.2.3", "2001:db8::1", "::ffff:10.1.2.3" })
        {
            for (var i = 0; i < 5; i++)
                Assert.False(bans.RecordFailure(ip));
            Assert.Equal(0, bans.FailuresFor(ip));
            Assert.False(bans.IsBanned(ip));
        }
        Assert.Equal(0, bans.TrackedFailures);
        Assert.Equal(0, bans.TrackedBans);

        // Another address is still counted and still banned.
        Assert.False(bans.RecordFailure("11.1.2.3"));
        Assert.True(bans.RecordFailure("11.1.2.3"));
        Assert.True(bans.IsBanned("11.1.2.3"));
    }

    // ---- The bounded tables --------------------------------------------------------------------------------

    [Fact]
    public void TheFailureTable_IsBounded_AndCountsItsEvictions()
    {
        var (bans, _, _) = Manager("limits:\n  auth_fail_max_per_ip: 100000");
        for (var i = 0; i < AuthBanManager.MaxTrackedIps + 10; i++)
            bans.RecordFailure($"10.{(i / 65536) % 256}.{(i / 256) % 256}.{i % 256}");

        Assert.True(bans.TrackedFailures <= AuthBanManager.MaxTrackedIps);
        Assert.Equal(10, bans.FailureEvictions);
        Assert.Equal(0, bans.TrackedBans);
    }

    [Fact]
    public void TheFailureTable_ForgetsTheEntriesWhoseWindowHasPassed()
    {
        // The entries expire by themselves: the failures of the first addresses are forgotten when the
        // window has passed, without those addresses ever coming back.
        var (bans, clock, _) = Manager("limits:\n  auth_fail_max_per_ip: 100\n  auth_fail_window_seconds: 600");
        for (var i = 0; i < 100; i++)
            bans.RecordFailure($"10.0.0.{i}");
        Assert.Equal(100, bans.TrackedFailures);

        // The window passes; the activity of other addresses sweeps the table.
        clock.Advance(TimeSpan.FromSeconds(601));
        for (var i = 0; i < 5; i++)
            bans.RecordFailure($"10.1.0.{i}");

        Assert.Equal(5, bans.TrackedFailures);
        Assert.Equal(0, bans.FailuresFor("10.0.0.0"));
        Assert.Equal(1, bans.FailuresFor("10.1.0.0"));
    }

    [Fact]
    public void TheBanTable_ForgetsTheBansThatHaveEnded()
    {
        // The bans expire by themselves too, and the sweep says so in the log.
        var (bans, clock, logs) = Manager("limits:\n  auth_fail_max_per_ip: 1\n  auth_ban_seconds: 60");
        for (var i = 0; i < 50; i++)
            Assert.True(bans.RecordFailure($"10.0.0.{i}"));
        Assert.Equal(50, bans.TrackedBans);

        // The bans end; the activity of another address sweeps them away.
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.True(bans.RecordFailure("10.1.0.1"));

        Assert.Equal(1, bans.TrackedBans);
        Assert.False(bans.IsBanned("10.0.0.0"));
        var ended = logs.Events.Count(e => e.Level == LogEventLevel.Debug
            && e.RenderMessage().Contains("ended"));
        Assert.Equal(50, ended);
    }

    [Fact]
    public void TheExpiryQueue_StaysBounded_WhenTheSameAddressesAreBannedAgainAndAgain()
    {
        // Five addresses are banned, their bans end and they are banned again, over and over. The queue
        // that orders the bans by the moment they end must not keep the entries of the bans that ended.
        var (bans, clock, _) = Manager("limits:\n  auth_fail_max_per_ip: 1\n  auth_ban_seconds: 60");
        var ips = Enumerable.Range(0, 5).Select(i => $"10.0.0.{i}").ToArray();
        for (var cycle = 0; cycle < 1000; cycle++)
        {
            foreach (var ip in ips)
            {
                Assert.True(bans.RecordFailure(ip));       // banned
                clock.Advance(TimeSpan.FromSeconds(61));   // the ban ends
                Assert.False(bans.IsBanned(ip));            // and is forgotten
            }
        }

        Assert.True(bans.ExpiryQueueCount <= AuthBanManager.MaxTrackedIps,
            $"the expiry queue grew to {bans.ExpiryQueueCount} entries");
        Assert.True(bans.ExpiryQueueCount <= AuthBanManager.SweepEveryInserts + bans.TrackedBans,
            $"the expiry queue kept the entries of the bans that ended: {bans.ExpiryQueueCount}");
    }

    [Fact]
    public void TheBanTable_IsBounded_AndEvictsTheBanThatEndsSoonest()
    {
        // Every ban is a second longer than the one before, so the first one ends soonest.
        var (bans, clock, _) = Manager("limits:\n  auth_fail_max_per_ip: 1\n  auth_ban_seconds: 604800");
        string first = "", second = "";
        for (var i = 0; i < AuthBanManager.MaxTrackedIps; i++)
        {
            var ip = $"10.{(i / 65536) % 256}.{(i / 256) % 256}.{i % 256}";
            if (i == 0) first = ip;
            if (i == 1) second = ip;
            Assert.True(bans.RecordFailure(ip));
            clock.Advance(TimeSpan.FromSeconds(1));
        }
        Assert.Equal(AuthBanManager.MaxTrackedIps, bans.TrackedBans);
        Assert.Equal(0, bans.BanEvictions);

        // The table is full: the ban that ends soonest is the one that goes.
        Assert.True(bans.RecordFailure("11.0.0.1"));
        Assert.Equal(AuthBanManager.MaxTrackedIps, bans.TrackedBans);
        Assert.Equal(1, bans.BanEvictions);
        Assert.False(bans.IsBanned(first));
        Assert.True(bans.IsBanned(second));
    }

    [Fact]
    public void TheEvictions_AreCountedInTheDropSummary()
    {
        // The tables of the broker count their evictions in the same summary as the dropped publishes.
        var hooks = Hooks("limits:\n  auth_fail_max_per_ip: 100000");
        for (var i = 0; i < AuthBanManager.MaxTrackedIps + 1; i++)
            hooks.Bans.RecordFailure($"10.{(i / 65536) % 256}.{(i / 256) % 256}.{i % 256}");

        var drops = hooks.Instance.Drops.Snapshot();
        Assert.True(drops.ContainsKey(AuthBanManager.FailureTableEvictionReason), "the eviction was not counted");
        Assert.Equal(1, drops[AuthBanManager.FailureTableEvictionReason]);
    }

    // ---- Concurrency ---------------------------------------------------------------------------------------

    [Fact]
    public async Task ParallelFailures_BanTheAddressOnce_AndLogItOnce()
    {
        var clock = new FakeClock();
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();
        var bans = new AuthBanManager(new LimitsConfig { AuthFailMaxPerIp = 10 }, clock, logger);

        const int threads = 32;
        using var barrier = new Barrier(threads);
        var workers = Enumerable.Range(0, threads).Select(_ => Task.Factory.StartNew(() =>
        {
            barrier.SignalAndWait();
            bans.RecordFailure("1.2.3.4");
        }, TestContext.Current.CancellationToken, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
        await Task.WhenAll(workers);

        Assert.True(bans.IsBanned("1.2.3.4"));
        var warning = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);
        Assert.StartsWith("Banned ", warning.MessageTemplate.Text);
        Assert.Contains("1.2.3.4", warning.Properties["RemoteIp"].ToString());
        Assert.Contains("10", warning.Properties["Failures"].ToString());
    }

    // ---- The connect hook ----------------------------------------------------------------------------------

    [Fact]
    public async Task ABadPassword_CountsAsAFailure()
    {
        var hooks = Hooks("limits:\n  auth_fail_max_per_ip: 10");
        var args = Args(new MqttConnectPacket { ClientId = "c1", Username = "meshdev", Password = Pw("wrong") });

        await hooks.ValidateConnectionAsync(args);

        Assert.Equal(MqttConnectReasonCode.BadUserNameOrPassword, args.ReasonCode);
        Assert.Equal(1, hooks.Bans.FailuresFor(RemoteIp));
    }

    [Fact]
    public async Task AnUnsupportedAuthenticationMethod_CountsAsAFailure()
    {
        var hooks = Hooks("limits:\n  auth_fail_max_per_ip: 10");
        var args = Args(new MqttConnectPacket { ClientId = "c1", Username = "meshdev", AuthenticationMethod = "SCRAM-SHA-1" });

        await hooks.ValidateConnectionAsync(args);

        Assert.Equal(MqttConnectReasonCode.BadAuthenticationMethod, args.ReasonCode);
        Assert.Equal(1, hooks.Bans.FailuresFor(RemoteIp));
    }

    [Fact]
    public async Task AFullPasswordQueue_IsNotCounted()
    {
        // One password-check slot and one pending check: the second login is told "server busy" without
        // its password ever being checked, so it is not a password failure.
        var hooks = Hooks("limits:\n  auth_fail_max_per_ip: 10\n  auth_max_pending: 1\n  auth_max_pending_per_user: 1",
            maxConcurrentKdf: 1);
        var firstArgs = Args(new MqttConnectPacket
            { ClientId = "c1", Username = "meshdev", Password = Pw("wrong-1") });
        var first = hooks.ValidateConnectionAsync(firstArgs);
        var secondArgs = Args(new MqttConnectPacket
            { ClientId = "c2", Username = "meshdev", Password = Pw("wrong-2") });
        await hooks.ValidateConnectionAsync(secondArgs);
        await first;

        Assert.Equal(MqttConnectReasonCode.ServerBusy, secondArgs.ReasonCode);
        Assert.Equal(MqttConnectReasonCode.BadUserNameOrPassword, firstArgs.ReasonCode);
        Assert.Equal(1, hooks.Bans.FailuresFor(RemoteIp));
    }

    [Fact]
    public async Task AClientIdConflict_IsNotCounted()
    {
        var hooks = Hooks("limits:\n  auth_fail_max_per_ip: 10", withAlice: true);
        var owner = Args(new MqttConnectPacket { ClientId = "shared", Username = "alice", Password = Pw("correct-horse") });
        await hooks.ValidateConnectionAsync(owner);
        Assert.Equal(MqttConnectReasonCode.Success, owner.ReasonCode);

        var conflict = Args(new MqttConnectPacket { ClientId = "shared", Username = "meshdev", Password = Pw("correct-horse") });
        await hooks.ValidateConnectionAsync(conflict);

        Assert.Equal(MqttConnectReasonCode.ClientIdentifierNotValid, conflict.ReasonCode);
        Assert.Equal(0, hooks.Bans.FailuresFor(RemoteIp));
    }

    [Fact]
    public async Task ASuccessfulLogin_DoesNotResetTheCounter()
    {
        // With the public meshdev credentials an attacker could interleave a correct login between the
        // guesses, so a success must not clear the failures of the address.
        var hooks = Hooks("limits:\n  auth_fail_max_per_ip: 3");
        await hooks.ValidateConnectionAsync(Args(new MqttConnectPacket
            { ClientId = "c1", Username = "meshdev", Password = Pw("wrong-1") }));
        await hooks.ValidateConnectionAsync(Args(new MqttConnectPacket
            { ClientId = "c2", Username = "meshdev", Password = Pw("wrong-2") }));
        Assert.Equal(2, hooks.Bans.FailuresFor(RemoteIp));

        var good = Args(new MqttConnectPacket { ClientId = "c3", Username = "meshdev", Password = Pw("correct-horse") });
        await hooks.ValidateConnectionAsync(good);
        Assert.Equal(MqttConnectReasonCode.Success, good.ReasonCode);
        Assert.Equal(2, hooks.Bans.FailuresFor(RemoteIp));

        await hooks.ValidateConnectionAsync(Args(new MqttConnectPacket
            { ClientId = "c4", Username = "meshdev", Password = Pw("wrong-3") }));
        Assert.True(hooks.Bans.IsBanned(RemoteIp));
    }

    [Fact]
    public async Task ABannedAddress_IsRefusedWithBanned_AndItsPasswordIsNeverChecked()
    {
        var hooks = Hooks("limits:\n  auth_fail_max_per_ip: 1");
        var logs = hooks.Logs;
        await hooks.ValidateConnectionAsync(Args(new MqttConnectPacket
            { ClientId = "c1", Username = "meshdev", Password = Pw("wrong") }));
        Assert.True(hooks.Bans.IsBanned(RemoteIp));
        var warnings = logs.Events.Count(e => e.Level == LogEventLevel.Warning);
        var kdfRuns = hooks.Authenticator.KdfRuns;

        var banned = Args(new MqttConnectPacket { ClientId = "c2", Username = "meshdev", Password = Pw("correct-horse") });
        await hooks.ValidateConnectionAsync(banned);

        Assert.Equal(MqttConnectReasonCode.Banned, banned.ReasonCode);
        Assert.Equal(kdfRuns, hooks.Authenticator.KdfRuns);   // the password was never checked
        Assert.Equal(warnings, logs.Events.Count(e => e.Level == LogEventLevel.Warning));   // no new Warning
        Assert.Equal(0, hooks.Bans.FailuresFor(RemoteIp));   // a banned refusal is not a new failure
    }

    [Fact]
    public async Task AfterTheBanTime_TheAddressMayLogInAgain()
    {
        var clock = new FakeClock();
        var hooks = Hooks("limits:\n  auth_fail_max_per_ip: 1\n  auth_ban_seconds: 60", time: clock);
        var wrong = Args(new MqttConnectPacket { ClientId = "c1", Username = "meshdev", Password = Pw("wrong") });
        await hooks.ValidateConnectionAsync(wrong);
        Assert.Equal(MqttConnectReasonCode.BadUserNameOrPassword, wrong.ReasonCode);
        Assert.True(hooks.Bans.IsBanned(RemoteIp));

        // While the ban lasts, the login is refused with "banned".
        var banned = Args(new MqttConnectPacket { ClientId = "c2", Username = "meshdev", Password = Pw("correct-horse") });
        await hooks.ValidateConnectionAsync(banned);
        Assert.Equal(MqttConnectReasonCode.Banned, banned.ReasonCode);

        // After the ban time the address may log in again.
        clock.Advance(TimeSpan.FromSeconds(60));
        var good = Args(new MqttConnectPacket { ClientId = "c3", Username = "meshdev", Password = Pw("correct-horse") });
        await hooks.ValidateConnectionAsync(good);
        Assert.Equal(MqttConnectReasonCode.Success, good.ReasonCode);
    }

    // ---- The helpers ---------------------------------------------------------------------------------------

    const string RemoteIp = "203.0.113.7";

    sealed class HookHarness
    {
        public BrokerHooks Instance { get; }
        public LogSink Logs { get; }
        public AuthBanManager Bans => Instance.Bans;
        public Authenticator Authenticator => Instance.Authenticator;

        public HookHarness(BrokerHooks instance, LogSink logs)
        {
            Instance = instance;
            Logs = logs;
        }

        public Task ValidateConnectionAsync(ValidatingConnectionEventArgs args) =>
            Instance.ValidateConnectionAsync(args);
    }

    static HookHarness Hooks(string limits, bool withAlice = false, int? maxConcurrentKdf = null, TimeProvider? time = null)
    {
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();
        var instance = new BrokerHooks(Config(limits, withAlice), logger, maxConcurrentKdf, time: time);
        return new HookHarness(instance, logs);
    }

    static ValidatingConnectionEventArgs Args(MqttConnectPacket packet) =>
        new(packet, new FakeAdapter(), new Hashtable(), CancellationToken.None);

    /// <summary>A channel adapter that only says where the connection comes from.</summary>
    sealed class FakeAdapter : IMqttChannelAdapter
    {
        readonly MqttPacketFormatterAdapter _formatter = new(MqttProtocolVersion.V311, new MqttBufferWriter(4096, 65535));

        public long BytesReceived => 0;
        public long BytesSent => 0;
        public X509Certificate2 ClientCertificate => null!;
        public EndPoint RemoteEndPoint { get; } = new IPEndPoint(IPAddress.Parse(RemoteIp), 40000);
        public EndPoint LocalEndPoint { get; } = new IPEndPoint(IPAddress.Loopback, 1883);
        public bool IsSecureConnection => false;
        public MqttPacketFormatterAdapter PacketFormatterAdapter => _formatter;
        public Task ConnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DisconnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<MqttPacket> ReceivePacketAsync(CancellationToken cancellationToken) => Task.FromResult<MqttPacket>(null!);
        public void ResetStatistics() { }
        public Task SendPacketAsync(MqttPacket packet, CancellationToken cancellationToken) => Task.CompletedTask;
        public void Dispose() { }
    }
}

using System.Text;
using Meshtastic.Mqtt;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

public class AuthTests
{
    // Generated with Python's hashlib.pbkdf2_hmac (an implementation independent of the broker).
    internal const string MeshdevHash = "pbkdf2-sha256$600000$iqngz3pWU8HFZn8xIv8/IQ==$ZhdEPkHgqnG2zbHe26j6U598nTyFTA8J/Kzm7WCxDuA=";
    internal const string AliceHash = "pbkdf2-sha256$100000$VndTagYWVdL7lFUTN6scLA==$Mwb7ppniGmLsMlyEJazbQewjWn5dHi8smEhnznBWRY0=";

    static Authenticator Build()
    {
        var config = ConfigLoader.Parse($"""
            users:
              - username: meshdev
                password_hash: "{MeshdevHash}"
              - username: alice
                password_hash: "{AliceHash}"
                subscribe_allow: [msh/ES/2/e/test/#]
            """);
        return new Authenticator(config.Users!);
    }

    static byte[] Pw(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public async Task CorrectPasswords_Authenticate()
    {
        var auth = Build();
        Assert.Equal(AuthResult.Success, await auth.AuthenticateAsync("meshdev", Pw("large4cats"), TestContext.Current.CancellationToken));
        Assert.Equal(AuthResult.Success, await auth.AuthenticateAsync("alice", Pw("correct-horse"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CachedSuccess_StillRejectsWrongPassword()
    {
        var auth = Build();
        Assert.Equal(AuthResult.Success, await auth.AuthenticateAsync("meshdev", Pw("large4cats"), TestContext.Current.CancellationToken));
        Assert.Equal(AuthResult.Success, await auth.AuthenticateAsync("meshdev", Pw("large4cats"), TestContext.Current.CancellationToken));
        Assert.Equal(AuthResult.Failed, await auth.AuthenticateAsync("meshdev", Pw("large4cats "), TestContext.Current.CancellationToken));
        Assert.Equal(AuthResult.Failed, await auth.AuthenticateAsync("meshdev", Pw("Large4cats"), TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("meshdev", "wrong")]
    [InlineData("meshdev", "")]
    [InlineData("alice", "large4cats")]          // another user's password
    [InlineData("MESHDEV", "large4cats")]        // usernames are case-sensitive
    [InlineData("nobody", "large4cats")]
    [InlineData("", "large4cats")]
    public async Task BadCredentials_AreRejected(string user, string password) =>
        Assert.Equal(AuthResult.Failed, await Build().AuthenticateAsync(user, Pw(password), TestContext.Current.CancellationToken));

    [Fact]
    public async Task NullCredentials_AreRejected()
    {
        var auth = Build();
        Assert.Equal(AuthResult.Failed, await auth.AuthenticateAsync(null, null, TestContext.Current.CancellationToken));
        Assert.Equal(AuthResult.Failed, await auth.AuthenticateAsync("meshdev", null, TestContext.Current.CancellationToken));
    }

    static Authenticator Build(int slots, TimeSpan timeout, int maxPending)
    {
        var config = ConfigLoader.Parse($"users:\n  - username: meshdev\n    password_hash: \"{MeshdevHash}\"\n");
        return new Authenticator(config.Users!, slots, timeout, maxPending);
    }

    [Fact]
    public async Task ConcurrentLoginsWithTheSamePassword_ShareOneKdf()
    {
        var auth = Build(slots: 1, TimeSpan.FromSeconds(30), maxPending: 64);
        var results = await Task.WhenAll(Enumerable.Range(0, 12)
            .Select(_ => auth.AuthenticateAsync("meshdev", Pw("large4cats"), TestContext.Current.CancellationToken)));
        Assert.All(results, r => Assert.Equal(AuthResult.Success, r));
        Assert.Equal(1, auth.KdfRuns);
    }

    [Fact]
    public async Task ConcurrentWrongPasswords_AreAllRejected()
    {
        // Coalescing is per (user, password): a wrong password never rides on a right one.
        var auth = Build(slots: 1, TimeSpan.FromSeconds(30), maxPending: 64);
        var good = auth.AuthenticateAsync("meshdev", Pw("large4cats"), TestContext.Current.CancellationToken);
        var bad = auth.AuthenticateAsync("meshdev", Pw("large4dogs"), TestContext.Current.CancellationToken);
        Assert.Equal(AuthResult.Success, await good);
        Assert.Equal(AuthResult.Failed, await bad);
    }

    [Fact]
    public async Task QueueOverflow_AnswersBusy_WithoutRunningTheKdf()
    {
        var auth = Build(slots: 1, TimeSpan.FromSeconds(30), maxPending: 2);
        var calls = Enumerable.Range(0, 10)
            .Select(i => auth.AuthenticateAsync("meshdev", Pw($"wrong-{i}"), TestContext.Current.CancellationToken))
            .ToArray();
        var results = await Task.WhenAll(calls);
        Assert.Equal(2, results.Count(r => r == AuthResult.Failed));
        Assert.Equal(8, results.Count(r => r == AuthResult.Busy));
        Assert.Equal(2, auth.KdfRuns);
    }

    [Fact]
    public async Task QueueTimeout_AnswersBusy()
    {
        var auth = Build(slots: 1, TimeSpan.FromMilliseconds(100), maxPending: 64);
        var results = await Task.WhenAll(Enumerable.Range(0, 6)
            .Select(i => auth.AuthenticateAsync("meshdev", Pw($"wrong-{i}"), TestContext.Current.CancellationToken)));
        Assert.Contains(AuthResult.Busy, results);
        Assert.True(auth.KdfRuns < 6);
    }

    [Fact]
    public async Task UnknownUsernames_UseTheirOwnLane()
    {
        // Unknown usernames saturate their single slot; a configured user is checked in its own lane.
        var auth = Build(slots: 1, TimeSpan.FromSeconds(30), maxPending: 4);
        var flood = Enumerable.Range(0, 20)
            .Select(i => auth.AuthenticateAsync($"nobody{i}", Pw("x"), TestContext.Current.CancellationToken))
            .ToArray();
        Assert.Equal(AuthResult.Success, await auth.AuthenticateAsync("meshdev", Pw("large4cats"), TestContext.Current.CancellationToken));
        var floodResults = await Task.WhenAll(flood);
        Assert.DoesNotContain(AuthResult.Success, floodResults);
        Assert.Contains(AuthResult.Busy, floodResults);
    }

    [Fact]
    public async Task MostAwaitedCheck_RunsFirst()
    {
        // 10 different wrong passwords for meshdev are queued first, then 10 nodes log in with the real one.
        // The real password has 10 waiters, each guess has 1: it runs right after the check already started.
        var auth = Build(slots: 1, TimeSpan.FromSeconds(30), maxPending: 64);
        var ct = TestContext.Current.CancellationToken;
        var guesses = Enumerable.Range(0, 10).Select(i => auth.AuthenticateAsync("meshdev", Pw($"guess-{i}"), ct)).ToArray();
        var nodes = Enumerable.Range(0, 10).Select(_ => auth.AuthenticateAsync("meshdev", Pw("large4cats"), ct)).ToArray();

        var results = await Task.WhenAll(nodes);
        var guessesDoneFirst = guesses.Count(t => t.IsCompleted);
        Assert.All(results, r => Assert.Equal(AuthResult.Success, r));
        // Only the guess that had already started may finish before the real password is served.
        Assert.True(guessesDoneFirst <= 1, $"the real password waited for {guessesDoneFirst} guesses");
        Assert.All(await Task.WhenAll(guesses), r => Assert.Equal(AuthResult.Failed, r));
    }

    [Fact]
    public void HashRoundTrip()
    {
        var encoded = PasswordHasher.Hash("s3cret", PasswordHasher.MinIterations);
        Assert.StartsWith("pbkdf2-sha256$100000$", encoded);
        Assert.True(PasswordHasher.TryParse(encoded, out var parsed, out _));
        Assert.True(parsed!.Verify(Pw("s3cret")));
        Assert.False(parsed.Verify(Pw("s3cret!")));
    }

    [Fact]
    public void Hash_UsesFreshSalt() =>
        Assert.NotEqual(PasswordHasher.Hash("x", PasswordHasher.MinIterations), PasswordHasher.Hash("x", PasswordHasher.MinIterations));

    [Fact]
    public void PythonHash_VerifiesInDotNet()
    {
        Assert.True(PasswordHasher.TryParse(MeshdevHash, out var parsed, out _));
        Assert.True(parsed!.Verify(Pw("large4cats")));
    }

    [Theory]
    [InlineData("large4cats")]                                                  // plaintext
    [InlineData("pbkdf2-sha256$600000$AAAA")]                                  // missing part
    [InlineData("bcrypt$600000$iqngz3pWU8HFZn8xIv8/IQ==$ZhdEPkHgqnG2zbHe26j6U598nTyFTA8J/Kzm7WCxDuA=")]
    [InlineData("pbkdf2-sha256$1000$iqngz3pWU8HFZn8xIv8/IQ==$ZhdEPkHgqnG2zbHe26j6U598nTyFTA8J/Kzm7WCxDuA=")]  // too few iterations
    [InlineData("pbkdf2-sha256$-5$iqngz3pWU8HFZn8xIv8/IQ==$ZhdEPkHgqnG2zbHe26j6U598nTyFTA8J/Kzm7WCxDuA=")]
    [InlineData("pbkdf2-sha256$600000$!!!$ZhdEPkHgqnG2zbHe26j6U598nTyFTA8J/Kzm7WCxDuA=")]
    [InlineData("pbkdf2-sha256$600000$AAAA$ZhdEPkHgqnG2zbHe26j6U598nTyFTA8J/Kzm7WCxDuA=")]                    // short salt
    [InlineData("pbkdf2-sha256$600000$iqngz3pWU8HFZn8xIv8/IQ==$AAAA")]                                        // short hash
    [InlineData("")]
    [InlineData(null)]
    public void MalformedHashes_AreRejected(string? encoded) =>
        Assert.False(PasswordHasher.TryParse(encoded, out _, out _));
}

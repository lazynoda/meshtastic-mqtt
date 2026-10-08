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
        Assert.True(await auth.AuthenticateAsync("meshdev", Pw("large4cats"), TestContext.Current.CancellationToken));
        Assert.True(await auth.AuthenticateAsync("alice", Pw("correct-horse"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CachedSuccess_StillRejectsWrongPassword()
    {
        var auth = Build();
        Assert.True(await auth.AuthenticateAsync("meshdev", Pw("large4cats"), TestContext.Current.CancellationToken));
        Assert.True(await auth.AuthenticateAsync("meshdev", Pw("large4cats"), TestContext.Current.CancellationToken));
        Assert.False(await auth.AuthenticateAsync("meshdev", Pw("large4cats "), TestContext.Current.CancellationToken));
        Assert.False(await auth.AuthenticateAsync("meshdev", Pw("Large4cats"), TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("meshdev", "wrong")]
    [InlineData("meshdev", "")]
    [InlineData("alice", "large4cats")]          // another user's password
    [InlineData("MESHDEV", "large4cats")]        // usernames are case-sensitive
    [InlineData("nobody", "large4cats")]
    [InlineData("", "large4cats")]
    public async Task BadCredentials_AreRejected(string user, string password) =>
        Assert.False(await Build().AuthenticateAsync(user, Pw(password), TestContext.Current.CancellationToken));

    [Fact]
    public async Task NullCredentials_AreRejected()
    {
        var auth = Build();
        Assert.False(await auth.AuthenticateAsync(null, null, TestContext.Current.CancellationToken));
        Assert.False(await auth.AuthenticateAsync("meshdev", null, TestContext.Current.CancellationToken));
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

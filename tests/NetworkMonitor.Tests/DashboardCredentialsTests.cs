using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Server.Auth;

namespace NetworkMonitor.Tests;

public class DashboardCredentialsTests
{
    private static readonly string Hash = DashboardCredentials.HashPassword("correct horse battery staple");

    [Fact]
    public void Verify_AcceptsTheRightUsernameAndPassword()
    {
        var creds = new DashboardCredentials("admin", Hash);
        Assert.True(creds.Verify("admin", "correct horse battery staple"));
    }

    [Theory]
    [InlineData("admin", "wrong password")]
    [InlineData("Admin", "correct horse battery staple")] // usernames are case-sensitive
    [InlineData("root", "correct horse battery staple")]
    [InlineData("admin", "")]
    [InlineData(null, null)]
    public void Verify_RejectsAnythingElse(string? username, string? password)
    {
        var creds = new DashboardCredentials("admin", Hash);
        Assert.False(creds.Verify(username, password));
    }

    [Fact]
    public void HashPassword_IsSalted()
    {
        Assert.NotEqual(DashboardCredentials.HashPassword("same"), DashboardCredentials.HashPassword("same"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("plaintext-password")]
    [InlineData("bm90LWEtaGFzaA==")] // valid base64, wrong format
    public void Constructor_RejectsValuesThatAreNotHashes(string notAHash)
    {
        Assert.Throws<InvalidOperationException>(() => new DashboardCredentials("admin", notAHash));
    }

    [Fact]
    public void FromConfiguration_WithoutHash_GeneratesAWorkingOneTimePassword()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection().Build();
        var logger = new CapturingLogger();

        DashboardCredentials creds = DashboardCredentials.FromConfiguration(config, logger);

        string message = Assert.Single(logger.Messages);
        string password = Regex.Match(message, "password '([^']+)'").Groups[1].Value;
        Assert.Equal(24, password.Length);
        Assert.Equal("admin", creds.Username);
        Assert.True(creds.Verify("admin", password));
        Assert.False(creds.Verify("admin", ""));
    }

    [Fact]
    public void FromConfiguration_UsesConfiguredUsernameAndHash()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Dashboard:Username"] = "george",
            ["Dashboard:PasswordHash"] = Hash,
        }).Build();
        var logger = new CapturingLogger();

        DashboardCredentials creds = DashboardCredentials.FromConfiguration(config, logger);

        Assert.Empty(logger.Messages); // nothing generated, nothing logged
        Assert.True(creds.Verify("george", "correct horse battery staple"));
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<string> Messages { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }
}

using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NetworkMonitor.Server.Auth;
using NetworkMonitor.Server.Services;

namespace NetworkMonitor.Tests;

/// <summary>Runs the real server pipeline in memory with a known login and no honeypot listeners.</summary>
public class MonitorAppFactory : WebApplicationFactory<Program>
{
    public const string Username = "tester";
    public const string Password = "correct horse battery staple";

    private readonly string _dataDir = Path.Combine(Path.GetTempPath(), "nm-tests-" + Guid.NewGuid().ToString("N"));

    protected virtual int LoginAttemptsPerMinute => 100;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(_dataDir);
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Monitor:DatabasePath"] = Path.Combine(_dataDir, "test.db"),
            ["Dashboard:Username"] = Username,
            ["Dashboard:PasswordHash"] = DashboardCredentials.HashPassword(Password),
            ["Dashboard:LoginAttemptsPerMinute"] = LoginAttemptsPerMinute.ToString(),
        }));

        builder.ConfigureTestServices(services =>
        {
            // Don't open the honeypot ports during tests.
            foreach (ServiceDescriptor listener in services.Where(d => d.ServiceType == typeof(IHostedService) &&
                         (d.ImplementationType == typeof(TcpListenerService) ||
                          d.ImplementationType == typeof(UdpListenerService))).ToList())
                services.Remove(listener);
        });
    }

    public HttpClient NewClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    /// <summary>Fetches the login page for its anti-forgery token, then posts the form.</summary>
    public static async Task<HttpResponseMessage> SignInAsync(
        HttpClient client, string username, string password, IDictionary<string, string>? extraFields = null)
    {
        string page = await client.GetStringAsync("/login");
        Match token = Regex.Match(page, "<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]+)\"");
        Assert.True(token.Success, "login page should carry an anti-forgery token");

        var fields = new Dictionary<string, string>
        {
            [token.Groups[1].Value] = token.Groups[2].Value,
            ["username"] = username,
            ["password"] = password,
        };
        foreach (var (key, value) in extraFields ?? new Dictionary<string, string>())
            fields[key] = value;

        return await client.PostAsync("/login", new FormUrlEncodedContent(fields));
    }

    public static string LocationPath(HttpResponseMessage response)
    {
        Uri location = response.Headers.Location ?? throw new InvalidOperationException("no Location header");
        return location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString.Split('?')[0];
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dataDir, recursive: true); } catch { /* best effort */ }
    }
}

public sealed class ThrottledAppFactory : MonitorAppFactory
{
    protected override int LoginAttemptsPerMinute => 2;
}

public sealed class DashboardAuthTests(MonitorAppFactory factory) : IClassFixture<MonitorAppFactory>
{
    [Theory]
    [InlineData("/api/connections")]
    [InlineData("/api/connections/1")]
    [InlineData("/api/stats")]
    [InlineData("/api/config")]
    public async Task Api_WithoutSignIn_Returns401(string path)
    {
        HttpResponseMessage response = await factory.NewClient().GetAsync(path);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task LiveFeedHub_WithoutSignIn_Returns401()
    {
        HttpResponseMessage response = await factory.NewClient()
            .PostAsync("/hub/monitor/negotiate?negotiateVersion=1", content: null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/index.html")]
    [InlineData("/_framework/blazor.webassembly.js")]
    [InlineData("/css/app.css")]
    public async Task DashboardPagesAndFiles_WithoutSignIn_RedirectToLogin(string path)
    {
        HttpResponseMessage response = await factory.NewClient().GetAsync(path);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/login", MonitorAppFactory.LocationPath(response));
    }

    [Fact]
    public async Task LoginPage_IsPublic_AndCannotBeFramed()
    {
        HttpResponseMessage response = await factory.NewClient().GetAsync("/login");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("<form method=\"post\" action=\"/login\">", await response.Content.ReadAsStringAsync());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
    }

    [Fact]
    public async Task CorrectLogin_GrantsAccess_AndSignOutRevokesIt()
    {
        HttpClient client = factory.NewClient();

        HttpResponseMessage signIn = await MonitorAppFactory.SignInAsync(
            client, MonitorAppFactory.Username, MonitorAppFactory.Password);
        Assert.Equal(HttpStatusCode.Redirect, signIn.StatusCode);
        Assert.Equal("/", MonitorAppFactory.LocationPath(signIn));

        HttpResponseMessage api = await client.GetAsync("/api/stats");
        Assert.Equal(HttpStatusCode.OK, api.StatusCode);
        Assert.Equal("no-store", api.Headers.CacheControl?.ToString());

        // The app shell must be revalidated each load so signing out can't leave a usable cached copy.
        HttpResponseMessage shell = await client.GetAsync("/");
        Assert.True(shell.Headers.CacheControl?.NoCache, "app shell should be served with Cache-Control: no-cache");
        Assert.True(shell.Headers.CacheControl?.Private);
        Assert.Equal(HttpStatusCode.OK,
            (await client.PostAsync("/hub/monitor/negotiate?negotiateVersion=1", content: null)).StatusCode);

        HttpResponseMessage signOut = await client.PostAsync("/logout", content: null);
        Assert.Equal("/login", MonitorAppFactory.LocationPath(signOut));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/stats")).StatusCode);
    }

    [Theory]
    [InlineData(MonitorAppFactory.Username, "wrong password")]
    [InlineData("admin", MonitorAppFactory.Password)]
    public async Task WrongCredentials_AreRejected(string username, string password)
    {
        HttpClient client = factory.NewClient();

        HttpResponseMessage signIn = await MonitorAppFactory.SignInAsync(client, username, password);

        Assert.Equal("/login", MonitorAppFactory.LocationPath(signIn));
        Assert.Contains("error=1", signIn.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/stats")).StatusCode);
    }

    [Fact]
    public async Task Login_WithoutAntiforgeryToken_IsRejected()
    {
        HttpClient client = factory.NewClient();

        HttpResponseMessage signIn = await client.PostAsync("/login", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["username"] = MonitorAppFactory.Username,
                ["password"] = MonitorAppFactory.Password,
            }));

        Assert.Contains("error=1", signIn.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/stats")).StatusCode);
    }

    [Fact]
    public async Task Login_IgnoresReturnUrl_SoItCannotRedirectOffSite()
    {
        HttpResponseMessage signIn = await MonitorAppFactory.SignInAsync(
            factory.NewClient(), MonitorAppFactory.Username, MonitorAppFactory.Password,
            new Dictionary<string, string> { ["ReturnUrl"] = "https://evil.example/phish" });

        Assert.Equal("/", signIn.Headers.Location!.OriginalString);
    }
}

public sealed class LoginRateLimitTests(ThrottledAppFactory factory) : IClassFixture<ThrottledAppFactory>
{
    [Fact]
    public async Task RepeatedSignInAttempts_AreThrottled()
    {
        HttpClient client = factory.NewClient();

        // The factory allows 2 attempts per minute.
        await MonitorAppFactory.SignInAsync(client, MonitorAppFactory.Username, "guess-1");
        await MonitorAppFactory.SignInAsync(client, MonitorAppFactory.Username, "guess-2");
        HttpResponseMessage third = await MonitorAppFactory.SignInAsync(
            client, MonitorAppFactory.Username, MonitorAppFactory.Password);

        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/stats")).StatusCode);
    }
}

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using NetworkMonitor.Server.Auth;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Server.Data;
using NetworkMonitor.Server.Handlers;
using NetworkMonitor.Server.Services;
using NetworkMonitor.Shared;

// `hash-password` prints a hash for Dashboard:PasswordHash and exits.
if (args is ["hash-password", ..])
{
    Environment.ExitCode = PasswordTool.Run();
    return;
}

var builder = WebApplication.CreateBuilder(args);

// ---- Configuration ------------------------------------------------------------------------
builder.Services.Configure<MonitorOptions>(builder.Configuration.GetSection(MonitorOptions.SectionName));
var monitorOptions = builder.Configuration.GetSection(MonitorOptions.SectionName).Get<MonitorOptions>() ?? new();

string dashboardUrl = builder.Configuration["Dashboard:Url"] ?? "http://0.0.0.0:8099";
builder.WebHost.UseUrls(dashboardUrl);

// ---- Persistence --------------------------------------------------------------------------
builder.Services.AddDbContext<MonitorDbContext>((sp, opt) =>
    opt.UseSqlite($"Data Source={sp.GetRequiredService<IOptions<MonitorOptions>>().Value.DatabasePath}"));

// The data-protection keys sign the login cookie; keep them next to the database so sessions
// survive restarts (in Docker that is the /data volume).
builder.Services.AddDataProtection().SetApplicationName("NetworkMonitor");
builder.Services.AddOptions<KeyManagementOptions>()
    .Configure<IOptions<MonitorOptions>, ILoggerFactory>((keys, monitor, loggers) =>
        keys.XmlRepository = new FileSystemXmlRepository(KeysDirectory(monitor.Value.DatabasePath), loggers));

// ---- Capture services ---------------------------------------------------------------------
builder.Services.AddSingleton<CertificateProvider>();
builder.Services.AddSingleton<SshHostKeyProvider>();
builder.Services.AddSingleton(sp =>
    new ConnectionLimiter(sp.GetRequiredService<IOptions<MonitorOptions>>().Value.Limits));
builder.Services.AddSingleton<IConnectionSink, ConnectionSink>();
builder.Services.AddSingleton<ProtocolHandlerResolver>();

// Protocol handlers (stateless singletons).
builder.Services.AddSingleton<RawCaptureHandler>();
builder.Services.AddSingleton<HttpHandler>();
builder.Services.AddSingleton<TlsHandler>();
builder.Services.AddSingleton<FtpHandler>();
builder.Services.AddSingleton<SmtpHandler>();
builder.Services.AddSingleton<Pop3Handler>();
builder.Services.AddSingleton<ImapHandler>();
builder.Services.AddSingleton<TelnetHandler>();
builder.Services.AddSingleton<RedisHandler>();
builder.Services.AddSingleton<SshHandler>();

// Listeners.
builder.Services.AddHostedService<TcpListenerService>();
builder.Services.AddHostedService<UdpListenerService>();

// ---- Web / dashboard ----------------------------------------------------------------------
builder.Services.AddSignalR();
builder.Services.AddDashboardAuth();

var app = builder.Build();

// Resolve the login now so a generated one-time password is logged at startup, and a bad
// Dashboard:PasswordHash stops the app immediately rather than on the first sign-in.
app.Services.GetRequiredService<DashboardCredentials>();
WarnIfDashboardIsPlainHttp(app, dashboardUrl);

// Create the database on first run.
using (IServiceScope scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<MonitorDbContext>();
    db.Database.EnsureCreated();
}

// Authentication must come before the static-file middleware so the app files are protected too.
app.UseDashboardAuth();

if (app.Environment.IsDevelopment())
    app.UseWebAssemblyDebugging();

app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

// ---- REST API -----------------------------------------------------------------------------
var api = app.MapGroup("/api");

api.MapGet("/connections", async (
    MonitorDbContext db, int? take, int? port, string? ip, string? q) =>
{
    IQueryable<ConnectionRecord> query = db.Connections.AsNoTracking().OrderByDescending(c => c.Id);

    if (port is int p)
        query = query.Where(c => c.Port == p);
    if (!string.IsNullOrWhiteSpace(ip))
        query = query.Where(c => c.RemoteIp.Contains(ip));
    if (!string.IsNullOrWhiteSpace(q))
        query = query.Where(c => c.Summary.Contains(q) || c.Notes.Contains(q));

    int limit = Math.Clamp(take ?? monitorOptions.HistoryPageSize, 1, 2000);
    List<ConnectionRecord> rows = await query.Take(limit).ToListAsync();
    return Results.Ok(rows.Select(r => r.ToDto()));
});

api.MapGet("/connections/{id:long}", async (MonitorDbContext db, long id) =>
{
    ConnectionRecord? row = await db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id);
    return row is null ? Results.NotFound() : Results.Ok(row.ToDto());
});

api.MapGet("/stats", async (MonitorDbContext db) =>
{
    var perPort = await db.Connections
        .GroupBy(c => new { c.Port, c.Service })
        .Select(g => new { g.Key.Port, g.Key.Service, Count = g.Count() })
        .ToListAsync();
    long total = await db.Connections.LongCountAsync();
    return Results.Ok(new { total, ports = perPort.OrderBy(p => p.Port) });
});

api.MapGet("/config", () => Results.Ok(new
{
    tcpPorts = monitorOptions.TcpPorts.Select(p => new { p.Port, p.Service }),
    udpPorts = monitorOptions.UdpPorts.Select(p => new { p.Port, p.Service }),
    limits = monitorOptions.Limits,
}));

app.MapDashboardAuth();
app.MapHub<MonitorHub>(HubContract.Path);
app.MapFallbackToFile("index.html");

app.Run();

static DirectoryInfo KeysDirectory(string databasePath) =>
    new(Path.Combine(Path.GetDirectoryName(Path.GetFullPath(databasePath)) ?? ".", "keys"));

static void WarnIfDashboardIsPlainHttp(WebApplication app, string urls)
{
    foreach (string url in urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        BindingAddress address = BindingAddress.Parse(url);
        string host = address.Host.Trim('[', ']');
        bool loopback = host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                        (System.Net.IPAddress.TryParse(host, out var ip) && System.Net.IPAddress.IsLoopback(ip));
        if (address.Scheme != "http" || loopback)
            continue;

        app.Logger.LogWarning(
            "The dashboard is served over plain HTTP on {Url}. The password and session cookie can be " +
            "intercepted on the network; serve it over HTTPS (see README) before exposing it to the internet.",
            url);
    }
}

public partial class Program { }

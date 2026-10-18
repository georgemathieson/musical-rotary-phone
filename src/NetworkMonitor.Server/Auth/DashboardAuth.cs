using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace NetworkMonitor.Server.Auth;

/// <summary>
/// Username/password protection for the dashboard web side: the Blazor app files, the REST API and
/// the SignalR hub. Every endpoint and static file requires a signed-in session unless it explicitly
/// allows anonymous access (only the login page does). The honeypot listeners are unaffected.
/// </summary>
public static class DashboardAuth
{
    private const string LoginRateLimitPolicy = "dashboard-login";

    public static IServiceCollection AddDashboardAuth(this IServiceCollection services)
    {
        services.AddSingleton(sp => DashboardCredentials.FromConfiguration(
            sp.GetRequiredService<IConfiguration>(),
            sp.GetRequiredService<ILoggerFactory>().CreateLogger("NetworkMonitor.Dashboard")));

        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.Cookie.Name = "nm_auth";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.LoginPath = "/login";
                options.ExpireTimeSpan = TimeSpan.FromHours(8);
                options.SlidingExpiration = true;
                options.Events.OnRedirectToLogin = context =>
                {
                    // Script callers (API, SignalR) get a 401 they can act on, not an HTML redirect.
                    if (IsScriptEndpoint(context.Request.Path))
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    else
                        context.Response.Redirect(context.RedirectUri);
                    return Task.CompletedTask;
                };
            });

        // Deny by default: anything without explicit [AllowAnonymous] needs a signed-in user,
        // including requests that match no endpoint (static files such as _framework/*).
        services.AddAuthorization(options => options.FallbackPolicy =
            new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

        services.AddAntiforgery(options =>
        {
            options.Cookie.Name = "nm_af";
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        });

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (context, ct) =>
            {
                context.HttpContext.Response.ContentType = "text/html; charset=utf-8";
                await context.HttpContext.Response.WriteAsync(LoginPage.Throttled, ct);
            };
            options.AddPolicy(LoginRateLimitPolicy, http =>
            {
                int perMinute = http.RequestServices.GetRequiredService<IConfiguration>()
                    .GetValue("Dashboard:LoginAttemptsPerMinute", 5);
                return RateLimitPartition.GetFixedWindowLimiter(
                    http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = Math.Max(1, perMinute),
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                    });
            });
        });

        return services;
    }

    /// <summary>Adds the auth middleware. Must run before the static-file middleware.</summary>
    public static WebApplication UseDashboardAuth(this WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            IHeaderDictionary headers = context.Response.Headers;
            headers.XFrameOptions = "DENY";
            headers.XContentTypeOptions = "nosniff";
            headers["Referrer-Policy"] = "no-referrer";
            // API data (captured credentials) is never cached. Everything else behind the login must be
            // revalidated on each load, so a signed-out browser cannot reopen the app from its cache.
            headers.CacheControl = IsScriptEndpoint(context.Request.Path) ? "no-store" : "no-cache, private";
            await next();
        });

        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        return app;
    }

    public static WebApplication MapDashboardAuth(this WebApplication app)
    {
        app.MapGet("/login", (HttpContext context, IAntiforgery antiforgery, string? error) =>
        {
            if (context.User.Identity?.IsAuthenticated == true)
                return Results.Redirect("/");

            AntiforgeryTokenSet tokens = antiforgery.GetAndStoreTokens(context);
            return Results.Content(
                LoginPage.Render(tokens.FormFieldName, tokens.RequestToken!, failed: error is not null),
                "text/html; charset=utf-8");
        }).AllowAnonymous();

        app.MapPost("/login", async (
            HttpContext context, IAntiforgery antiforgery, DashboardCredentials credentials, ILoggerFactory loggers) =>
        {
            ILogger logger = loggers.CreateLogger("NetworkMonitor.Dashboard");
            string ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            try
            {
                await antiforgery.ValidateRequestAsync(context);
            }
            catch (AntiforgeryValidationException)
            {
                logger.LogWarning("Rejected dashboard sign-in from {Ip}: missing or invalid anti-forgery token", ip);
                return Results.Redirect("/login?error=1");
            }

            IFormCollection form = await context.Request.ReadFormAsync();
            if (!credentials.Verify(form["username"], form["password"]))
            {
                logger.LogWarning("Failed dashboard sign-in from {Ip}", ip);
                return Results.Redirect("/login?error=1");
            }

            var identity = new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Name, credentials.Username) },
                CookieAuthenticationDefaults.AuthenticationScheme);
            await context.SignInAsync(new ClaimsPrincipal(identity));
            logger.LogInformation("Dashboard sign-in from {Ip}", ip);

            // Always land on the dashboard: there is only one page, and ignoring any return URL
            // means the login cannot be used as an open redirect.
            return Results.Redirect("/");
        }).AllowAnonymous().RequireRateLimiting(LoginRateLimitPolicy);

        app.MapPost("/logout", async (HttpContext context) =>
        {
            await context.SignOutAsync();
            return Results.Redirect("/login");
        });

        return app;
    }

    private static bool IsScriptEndpoint(PathString path) =>
        path.StartsWithSegments("/api") || path.StartsWithSegments("/hub");
}

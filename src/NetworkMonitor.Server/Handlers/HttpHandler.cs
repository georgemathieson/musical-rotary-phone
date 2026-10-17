using System.Text;
using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Handlers;

/// <summary>
/// Reads an HTTP request, logging the method, path, headers, Basic-auth credentials and any
/// login form fields, then returns a generic 401 and closes. Shared by plain HTTP and, after
/// TLS termination, by HTTPS.
/// </summary>
public sealed class HttpHandler : TextProtocolHandler, IProtocolHandler
{
    public Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct)
        => ProcessAsync(session, stream, "http", ct);

    public async Task ProcessAsync(CaptureSession session, Stream stream, string scheme, CancellationToken ct)
    {
        string? requestLine = await ReadLineAsync(stream, ct);
        if (string.IsNullOrEmpty(requestLine))
            return;

        session.Note($"{scheme.ToUpperInvariant()} request: {requestLine}");
        string[] rl = requestLine.Split(' ');
        string method = rl.Length > 0 ? rl[0] : "";
        string path = rl.Length > 1 ? rl[1] : "";
        session.Summary = $"{method} {path}".Trim();

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int headerCount = 0;
        while (headerCount++ < 100)
        {
            string? header = await ReadLineAsync(stream, ct);
            if (string.IsNullOrEmpty(header))
                break;
            session.Note($"  {header}");
            int colon = header.IndexOf(':');
            if (colon > 0)
                headers[header[..colon].Trim()] = header[(colon + 1)..].Trim();
        }

        if (headers.TryGetValue("Authorization", out string? auth))
            CaptureAuthorization(session, auth);

        // Read a small request body (login forms are tiny) if the client announced one.
        string body = "";
        if (headers.TryGetValue("Content-Length", out string? clRaw) &&
            int.TryParse(clRaw, out int cl) && cl is > 0 and <= 8192)
        {
            var buf = new byte[cl];
            int got = 0;
            while (got < cl)
            {
                int n = await stream.ReadAsync(buf.AsMemory(got, cl - got), ct);
                if (n == 0) break;
                got += n;
            }
            body = Encoding.UTF8.GetString(buf, 0, got);
            if (body.Length > 0)
            {
                session.Note($"  body: {body}");
                CaptureForm(session, headers, body);
            }
        }

        string realm = scheme == "https" ? "Secure Area" : "Router";
        string page = "<html><head><title>401 Unauthorized</title></head>" +
                      "<body><h1>401 Unauthorized</h1></body></html>";
        string response =
            "HTTP/1.1 401 Unauthorized\r\n" +
            $"WWW-Authenticate: Basic realm=\"{realm}\"\r\n" +
            "Server: nginx\r\n" +
            "Content-Type: text/html; charset=utf-8\r\n" +
            $"Content-Length: {page.Length}\r\n" +
            "Connection: close\r\n\r\n" + page;
        await SendAsync(stream, response, ct);
    }

    private static void CaptureAuthorization(CaptureSession session, string auth)
    {
        if (auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(auth[6..].Trim()));
                int sep = decoded.IndexOf(':');
                string user = sep >= 0 ? decoded[..sep] : decoded;
                string pass = sep >= 0 ? decoded[(sep + 1)..] : "";
                session.AddCredential(new CredentialAttemptDto
                {
                    Service = "HTTP", Username = user, Password = pass, Detail = "Basic auth"
                });
                session.Summary = $"HTTP Basic {user} / {pass}";
            }
            catch { session.Note("  (unparseable Basic auth header)"); }
        }
        else
        {
            session.AddCredential(new CredentialAttemptDto
            {
                Service = "HTTP", Username = null, Password = auth, Detail = "Authorization header"
            });
        }
    }

    private static void CaptureForm(CaptureSession session, Dictionary<string, string> headers, string body)
    {
        if (!headers.TryGetValue("Content-Type", out string? ctype) ||
            !ctype.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return;

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string pair in body.Split('&'))
        {
            string[] kv = pair.Split('=', 2);
            if (kv.Length == 2)
                fields[Uri.UnescapeDataString(kv[0])] = Uri.UnescapeDataString(kv[1]);
        }

        string? user = Pick(fields, "username", "user", "login", "email", "uname");
        string? pass = Pick(fields, "password", "pass", "passwd", "pwd");
        if (user is not null || pass is not null)
        {
            session.AddCredential(new CredentialAttemptDto
            {
                Service = "HTTP", Username = user, Password = pass, Detail = "login form"
            });
            session.Summary = $"HTTP form {user ?? "?"} / {pass ?? "?"}";
        }
    }

    private static string? Pick(Dictionary<string, string> fields, params string[] keys)
    {
        foreach (string k in keys)
            if (fields.TryGetValue(k, out string? v))
                return v;
        return null;
    }
}

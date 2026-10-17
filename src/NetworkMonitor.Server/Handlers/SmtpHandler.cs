using System.Text;
using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Handlers;

/// <summary>
/// Plays a minimal SMTP server (RFC 5321) advertising AUTH LOGIN/PLAIN so it can capture
/// SMTP credentials and the mail envelope spammers try. Always rejects.
/// </summary>
public sealed class SmtpHandler : TextProtocolHandler, IProtocolHandler
{
    public async Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct)
    {
        await SendAsync(stream, (config.Banner ?? "220 mail.local ESMTP Postfix") + "\r\n", ct);

        int commands = 0;
        while (commands++ < 30 && !ct.IsCancellationRequested)
        {
            string? line = await ReadLineAsync(stream, ct);
            if (line is null)
                break;

            string verb = line.Split(' ', 2)[0].ToUpperInvariant();
            string arg = line.Length > verb.Length ? line[verb.Length..].Trim() : "";
            session.Note($"SMTP> {line}");

            switch (verb)
            {
                case "HELO":
                    await SendAsync(stream, "250 mail.local\r\n", ct);
                    break;
                case "EHLO":
                    await SendAsync(stream, "250-mail.local\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n", ct);
                    break;
                case "AUTH":
                    await HandleAuthAsync(session, stream, arg, ct);
                    break;
                case "MAIL":
                case "RCPT":
                    session.Note($"SMTP envelope: {line}");
                    await SendAsync(stream, "250 OK\r\n", ct);
                    break;
                case "QUIT":
                    await SendAsync(stream, "221 Bye\r\n", ct);
                    return;
                default:
                    await SendAsync(stream, "502 5.5.2 Command not recognized\r\n", ct);
                    break;
            }
        }
    }

    private static async Task HandleAuthAsync(CaptureSession session, Stream stream, string arg, CancellationToken ct)
    {
        string[] parts = arg.Split(' ', 2);
        string mechanism = parts[0].ToUpperInvariant();

        if (mechanism == "PLAIN")
        {
            string b64 = parts.Length > 1 ? parts[1] : await Prompt(stream, "334 \r\n", ct);
            // AUTH PLAIN payload is [authzid] NUL authcid NUL passwd
            string decoded = TryBase64(b64);
            string[] fields = decoded.Split('\0');
            string? user = fields.Length >= 2 ? fields[^2] : null;
            string? pass = fields.Length >= 1 ? fields[^1] : null;
            Record(session, user, pass, "AUTH PLAIN");
        }
        else if (mechanism == "LOGIN")
        {
            string userB64 = await Prompt(stream, "334 VXNlcm5hbWU6\r\n", ct); // "Username:"
            string passB64 = await Prompt(stream, "334 UGFzc3dvcmQ6\r\n", ct); // "Password:"
            Record(session, TryBase64(userB64), TryBase64(passB64), "AUTH LOGIN");
        }
        else
        {
            await SendAsync(stream, "504 5.7.4 Unrecognized authentication type\r\n", ct);
            return;
        }

        await SendAsync(stream, "535 5.7.8 Authentication credentials invalid\r\n", ct);
    }

    private static async Task<string> Prompt(Stream stream, string prompt, CancellationToken ct)
    {
        await SendAsync(stream, prompt, ct);
        return await ReadLineAsync(stream, ct) ?? "";
    }

    private static void Record(CaptureSession session, string? user, string? pass, string detail)
    {
        session.AddCredential(new CredentialAttemptDto
        {
            Service = "SMTP", Username = user, Password = pass, Detail = detail
        });
        session.Summary = $"SMTP {detail} {user ?? "?"} / {pass ?? "?"}";
    }

    private static string TryBase64(string value)
    {
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(value.Trim())); }
        catch { return value; }
    }
}

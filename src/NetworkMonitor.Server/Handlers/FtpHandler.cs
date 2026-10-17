using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Handlers;

/// <summary>Plays a minimal FTP server (RFC 959) to capture USER / PASS attempts. Always rejects.</summary>
public sealed class FtpHandler : TextProtocolHandler, IProtocolHandler
{
    public async Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct)
    {
        string banner = config.Banner ?? "220 (vsFTPd 3.0.5)";
        await SendAsync(stream, banner + "\r\n", ct);

        string? pendingUser = null;
        int commands = 0;

        while (commands++ < 20 && !ct.IsCancellationRequested)
        {
            string? line = await ReadLineAsync(stream, ct);
            if (line is null)
                break;

            string verb = line.Split(' ', 2)[0].ToUpperInvariant();
            string arg = line.Length > verb.Length ? line[verb.Length..].Trim() : "";
            session.Note($"FTP> {line}");

            switch (verb)
            {
                case "USER":
                    pendingUser = arg;
                    await SendAsync(stream, "331 Please specify the password.\r\n", ct);
                    break;
                case "PASS":
                    session.AddCredential(new CredentialAttemptDto
                    {
                        Service = "FTP", Username = pendingUser, Password = arg, Detail = "USER/PASS"
                    });
                    session.Summary = $"FTP login {pendingUser ?? "?"} / {arg}";
                    await SendAsync(stream, "530 Login incorrect.\r\n", ct);
                    break;
                case "QUIT":
                    await SendAsync(stream, "221 Goodbye.\r\n", ct);
                    return;
                case "SYST":
                    await SendAsync(stream, "215 UNIX Type: L8\r\n", ct);
                    break;
                case "FEAT":
                    await SendAsync(stream, "211-Features:\r\n UTF8\r\n211 End\r\n", ct);
                    break;
                default:
                    await SendAsync(stream, "530 Please login with USER and PASS.\r\n", ct);
                    break;
            }
        }
    }
}

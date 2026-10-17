using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Handlers;

/// <summary>Plays a minimal POP3 server (RFC 1939) to capture USER / PASS attempts. Always rejects.</summary>
public sealed class Pop3Handler : TextProtocolHandler, IProtocolHandler
{
    public async Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct)
    {
        await SendAsync(stream, (config.Banner ?? "+OK POP3 ready") + "\r\n", ct);

        string? pendingUser = null;
        int commands = 0;

        while (commands++ < 20 && !ct.IsCancellationRequested)
        {
            string? line = await ReadLineAsync(stream, ct);
            if (line is null)
                break;

            string verb = line.Split(' ', 2)[0].ToUpperInvariant();
            string arg = line.Length > verb.Length ? line[verb.Length..].Trim() : "";
            session.Note($"POP3> {line}");

            switch (verb)
            {
                case "USER":
                    pendingUser = arg;
                    await SendAsync(stream, "+OK\r\n", ct);
                    break;
                case "PASS":
                    session.AddCredential(new CredentialAttemptDto
                    {
                        Service = "POP3", Username = pendingUser, Password = arg, Detail = "USER/PASS"
                    });
                    session.Summary = $"POP3 login {pendingUser ?? "?"} / {arg}";
                    await SendAsync(stream, "-ERR authentication failed\r\n", ct);
                    break;
                case "CAPA":
                    await SendAsync(stream, "+OK\r\nUSER\r\n.\r\n", ct);
                    break;
                case "QUIT":
                    await SendAsync(stream, "+OK bye\r\n", ct);
                    return;
                default:
                    await SendAsync(stream, "-ERR unknown command\r\n", ct);
                    break;
            }
        }
    }
}

using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Handlers;

/// <summary>Plays a minimal IMAP server (RFC 3501) to capture tagged LOGIN attempts. Always rejects.</summary>
public sealed class ImapHandler : TextProtocolHandler, IProtocolHandler
{
    public async Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct)
    {
        await SendAsync(stream, (config.Banner ?? "* OK IMAP4rev1 Service Ready") + "\r\n", ct);

        int commands = 0;
        while (commands++ < 20 && !ct.IsCancellationRequested)
        {
            string? line = await ReadLineAsync(stream, ct);
            if (line is null)
                break;

            session.Note($"IMAP> {line}");
            string[] parts = line.Split(' ', 3);
            string tag = parts.Length > 0 ? parts[0] : "*";
            string command = parts.Length > 1 ? parts[1].ToUpperInvariant() : "";

            switch (command)
            {
                case "LOGIN":
                    (string? user, string? pass) = ParseLogin(parts.Length > 2 ? parts[2] : "");
                    session.AddCredential(new CredentialAttemptDto
                    {
                        Service = "IMAP", Username = user, Password = pass, Detail = "LOGIN"
                    });
                    session.Summary = $"IMAP login {user ?? "?"} / {pass ?? "?"}";
                    await SendAsync(stream, $"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n", ct);
                    break;
                case "CAPABILITY":
                    await SendAsync(stream, $"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n{tag} OK CAPABILITY completed\r\n", ct);
                    break;
                case "LOGOUT":
                    await SendAsync(stream, $"* BYE Logging out\r\n{tag} OK LOGOUT completed\r\n", ct);
                    return;
                default:
                    await SendAsync(stream, $"{tag} BAD Command unrecognized\r\n", ct);
                    break;
            }
        }
    }

    /// <summary>Parses the arguments of IMAP LOGIN, handling quoted values.</summary>
    private static (string? User, string? Pass) ParseLogin(string args)
    {
        var tokens = new List<string>();
        int i = 0;
        while (i < args.Length && tokens.Count < 2)
        {
            while (i < args.Length && args[i] == ' ') i++;
            if (i >= args.Length) break;

            if (args[i] == '"')
            {
                int end = args.IndexOf('"', i + 1);
                if (end < 0) { tokens.Add(args[(i + 1)..]); break; }
                tokens.Add(args[(i + 1)..end]);
                i = end + 1;
            }
            else
            {
                int end = args.IndexOf(' ', i);
                if (end < 0) { tokens.Add(args[i..]); break; }
                tokens.Add(args[i..end]);
                i = end;
            }
        }
        return (tokens.Count > 0 ? tokens[0] : null, tokens.Count > 1 ? tokens[1] : null);
    }
}

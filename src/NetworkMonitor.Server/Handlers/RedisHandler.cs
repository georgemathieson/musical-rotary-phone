using System.Text;
using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Handlers;

/// <summary>
/// Plays a minimal Redis server, parsing the RESP protocol so it can capture AUTH passwords
/// and the commands scanners run against exposed Redis. It never stores or returns any data.
/// </summary>
public sealed class RedisHandler : IProtocolHandler
{
    public async Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct)
    {
        int commands = 0;
        while (commands++ < 30 && !ct.IsCancellationRequested)
        {
            List<string>? args = await ReadCommandAsync(stream, ct);
            if (args is null || args.Count == 0)
                break;

            string cmd = args[0].ToUpperInvariant();
            session.Note($"Redis> {string.Join(' ', args)}");

            switch (cmd)
            {
                case "AUTH":
                    // AUTH <password>  or  AUTH <username> <password> (ACL, Redis 6+)
                    string? user = args.Count == 3 ? args[1] : null;
                    string pass = args[^1];
                    session.AddCredential(new CredentialAttemptDto
                    {
                        Service = "Redis", Username = user, Password = pass, Detail = "AUTH"
                    });
                    session.Summary = $"Redis AUTH {(user is null ? "" : user + " / ")}{pass}";
                    await WriteAsync(stream, "-WRONGPASS invalid username-password pair or user is disabled.\r\n", ct);
                    break;
                case "PING":
                    await WriteAsync(stream, "+PONG\r\n", ct);
                    break;
                case "QUIT":
                    await WriteAsync(stream, "+OK\r\n", ct);
                    return;
                default:
                    await WriteAsync(stream, "-NOAUTH Authentication required.\r\n", ct);
                    break;
            }
        }
    }

    private static async Task WriteAsync(Stream stream, string text, CancellationToken ct)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes(text), ct);
        await stream.FlushAsync(ct);
    }

    /// <summary>Reads one command, either a RESP array (*N) or an inline space-separated line.</summary>
    private static async Task<List<string>?> ReadCommandAsync(Stream stream, CancellationToken ct)
    {
        string? first = await ReadLineAsync(stream, ct);
        if (first is null)
            return null;

        if (!first.StartsWith('*'))
            return first.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

        if (!int.TryParse(first.AsSpan(1), out int count) || count is < 0 or > 1024)
            return null;

        var args = new List<string>(count);
        for (int i = 0; i < count; i++)
        {
            string? lenLine = await ReadLineAsync(stream, ct);
            if (lenLine is null || !lenLine.StartsWith('$') || !int.TryParse(lenLine.AsSpan(1), out int len) || len is < 0 or > 65536)
                return args;
            string? value = await ReadLineAsync(stream, ct);
            args.Add(value ?? "");
        }
        return args;
    }

    private static async Task<string?> ReadLineAsync(Stream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var one = new byte[1];
        while (true)
        {
            if (await stream.ReadAsync(one, ct) == 0)
                return sb.Length == 0 ? null : sb.ToString();
            if (one[0] == (byte)'\n')
                return sb.ToString().TrimEnd('\r');
            if (sb.Length < 65536)
                sb.Append((char)one[0]);
        }
    }
}

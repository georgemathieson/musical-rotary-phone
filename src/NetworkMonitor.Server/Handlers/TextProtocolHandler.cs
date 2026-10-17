using System.Text;
using NetworkMonitor.Server.Capture;

namespace NetworkMonitor.Server.Handlers;

/// <summary>Shared helpers for line-oriented, text-based protocols (FTP, SMTP, POP3, …).</summary>
public abstract class TextProtocolHandler
{
    /// <summary>Upper bound on a single line, so a peer cannot force unbounded buffering.</summary>
    protected const int MaxLineLength = 4096;

    protected static async Task SendAsync(Stream stream, string text, CancellationToken ct)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text);
        await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one CRLF/LF-terminated line as ASCII. Returns null on end-of-stream/idle.
    /// The trailing newline is stripped.
    /// </summary>
    protected static async Task<string?> ReadLineAsync(Stream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var one = new byte[1];
        while (true)
        {
            int read = await stream.ReadAsync(one, ct).ConfigureAwait(false);
            if (read == 0)
                return sb.Length == 0 ? null : sb.ToString();

            byte b = one[0];
            if (b == (byte)'\n')
                return sb.ToString().TrimEnd('\r');

            if (sb.Length < MaxLineLength)
                sb.Append((char)b);
        }
    }
}

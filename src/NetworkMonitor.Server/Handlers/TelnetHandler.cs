using System.Text;
using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Handlers;

/// <summary>
/// Plays a login prompt over Telnet, capturing the username/password pairs brute-forcers try.
/// Telnet IAC negotiation bytes are answered with refusals and stripped from the captured text.
/// </summary>
public sealed class TelnetHandler : IProtocolHandler
{
    private const byte IAC = 255, DONT = 254, DO = 253, WONT = 252, WILL = 251, SB = 250, SE = 240;

    public async Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct)
    {
        string host = config.Banner ?? "ubuntu";
        await WriteAsync(stream, $"\r\n{host} login: ", ct);

        for (int attempt = 0; attempt < 3 && !ct.IsCancellationRequested; attempt++)
        {
            string? user = await ReadLineAsync(stream, ct);
            if (user is null) return;

            await WriteAsync(stream, "Password: ", ct);
            string? pass = await ReadLineAsync(stream, ct);
            if (pass is null) return;

            session.AddCredential(new CredentialAttemptDto
            {
                Service = "Telnet", Username = user, Password = pass, Detail = "login prompt"
            });
            session.Note($"Telnet login attempt: {user} / {pass}");
            if (attempt == 0)
                session.Summary = $"Telnet login {user} / {pass}";

            await WriteAsync(stream, "\r\nLogin incorrect\r\n", ct);
            await WriteAsync(stream, $"{host} login: ", ct);
        }
    }

    private static async Task WriteAsync(Stream stream, string text, CancellationToken ct)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text);
        await stream.WriteAsync(bytes, ct);
        await stream.FlushAsync(ct);
    }

    private static async Task<string?> ReadLineAsync(Stream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var one = new byte[1];
        while (true)
        {
            if (await stream.ReadAsync(one, ct) == 0)
                return sb.Length == 0 ? null : sb.ToString();

            byte b = one[0];
            if (b == IAC)
            {
                await ConsumeIacAsync(stream, one, ct);
                continue;
            }
            if (b == (byte)'\n')
                return sb.ToString().TrimEnd('\r');
            if (b == 0)
                continue;
            if (sb.Length < 512)
                sb.Append((char)b);
        }
    }

    /// <summary>Swallows one Telnet IAC sequence (negotiation or subnegotiation).</summary>
    private static async Task ConsumeIacAsync(Stream stream, byte[] one, CancellationToken ct)
    {
        if (await stream.ReadAsync(one, ct) == 0) return;
        byte verb = one[0];
        if (verb is DO or DONT or WILL or WONT)
        {
            if (await stream.ReadAsync(one, ct) == 0) return; // option byte
        }
        else if (verb == SB)
        {
            while (await stream.ReadAsync(one, ct) != 0)
                if (one[0] == SE) break;
        }
    }
}

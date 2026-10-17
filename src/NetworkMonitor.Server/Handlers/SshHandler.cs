using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Server.Services;
using NetworkMonitor.Server.Ssh;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Handlers;

/// <summary>
/// Acts as a fake SSH server: it completes a real key exchange so the client proceeds to
/// authenticate, records every username/password (and public-key) attempt, and rejects them
/// all. No shell or session is ever provided.
/// </summary>
public sealed class SshHandler(SshHostKeyProvider hostKey, ILogger<SshHandler> logger) : IProtocolHandler
{
    private const int MaxAuthAttempts = 6;

    public async Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct)
    {
        using var transport = new SshTransport(stream, hostKey, session.Note);

        bool ready;
        try
        {
            ready = await transport.PerformHandshakeAsync(ct);
        }
        catch (Exception ex)
        {
            session.Note($"SSH handshake aborted: {ex.Message}");
            logger.LogDebug(ex, "SSH handshake aborted for {Ip}", session.RemoteIp);
            return;
        }

        if (!ready)
        {
            session.Note("SSH client disconnected before authentication.");
            return;
        }

        int attempts = 0;
        while (attempts < MaxAuthAttempts && !ct.IsCancellationRequested)
        {
            byte[] payload;
            try
            {
                payload = await transport.ReadPacketAsync(ct);
            }
            catch (Exception ex) when (ex is EndOfStreamException or IOException)
            {
                session.Note("SSH client disconnected.");
                return;
            }
            if (payload.Length == 0)
                break;

            switch (payload[0])
            {
                case SshMessage.ServiceRequest:
                    await AcceptServiceAsync(transport, payload, ct);
                    break;

                case SshMessage.UserAuthRequest:
                    attempts++;
                    bool handled = await HandleAuthRequestAsync(session, transport, payload, ct);
                    if (!handled)
                        return;
                    break;

                case SshMessage.Disconnect:
                    session.Note("SSH client sent DISCONNECT.");
                    return;

                default:
                    // Ignore keep-alives, debug messages, etc.
                    break;
            }
        }

        // Politely end the session after too many attempts.
        await SendDisconnectAsync(transport, ct);
    }

    private static async Task AcceptServiceAsync(SshTransport transport, byte[] payload, CancellationToken ct)
    {
        var reader = new SshReader(payload);
        reader.Byte();
        string service = reader.Utf8String();
        byte[] accept = new SshWriter().Byte(SshMessage.ServiceAccept).String(service).ToArray();
        await transport.WritePacketAsync(accept, ct);
    }

    private async Task<bool> HandleAuthRequestAsync(
        CaptureSession session, SshTransport transport, byte[] payload, CancellationToken ct)
    {
        var reader = new SshReader(payload);
        reader.Byte();
        string username = reader.Utf8String();
        reader.Utf8String(); // service name
        string method = reader.Utf8String();

        switch (method)
        {
            case "password":
            {
                reader.Boolean(); // change-password flag
                string password = reader.Utf8String();
                Record(session, username, password, "password");
                await SendAuthFailureAsync(transport, ct);
                return true;
            }

            case "keyboard-interactive":
            {
                string? password = await RunKeyboardInteractiveAsync(transport, ct);
                Record(session, username, password, "keyboard-interactive");
                await SendAuthFailureAsync(transport, ct);
                return true;
            }

            case "publickey":
            {
                reader.Boolean();                 // has-signature
                string keyAlgorithm = reader.Utf8String();
                session.Note($"SSH public-key attempt: user={username}, algorithm={keyAlgorithm}");
                if (string.IsNullOrEmpty(session.Summary))
                    session.Summary = $"SSH publickey {username} ({keyAlgorithm})";
                await SendAuthFailureAsync(transport, ct);
                return true;
            }

            default: // "none" probe and anything else
                session.Note($"SSH auth probe: user={username}, method={method}");
                await SendAuthFailureAsync(transport, ct);
                return true;
        }
    }

    /// <summary>Sends a single hidden "Password:" prompt and reads the response.</summary>
    private static async Task<string?> RunKeyboardInteractiveAsync(SshTransport transport, CancellationToken ct)
    {
        byte[] infoRequest = new SshWriter()
            .Byte(SshMessage.UserAuthInfoRequest)
            .String("")            // name
            .String("")            // instruction
            .String("")            // language tag
            .UInt32(1)             // one prompt
            .String("Password: ")
            .Boolean(false)        // echo off
            .ToArray();
        await transport.WritePacketAsync(infoRequest, ct);

        byte[] response = await transport.ReadPacketAsync(ct);
        if (response.Length == 0 || response[0] != SshMessage.UserAuthInfoResponse)
            return null;

        var reader = new SshReader(response);
        reader.Byte();
        uint count = reader.UInt32();
        return count >= 1 ? reader.Utf8String() : null;
    }

    private static void Record(CaptureSession session, string username, string? password, string method)
    {
        session.AddCredential(new CredentialAttemptDto
        {
            Service = "SSH", Username = username, Password = password, Detail = method
        });
        if (string.IsNullOrEmpty(session.Summary) ||
            session.Summary.Contains("publickey") || session.Summary.Contains("probe"))
        {
            session.Summary = $"SSH {method} login {username} / {password}";
        }
        session.Note($"SSH login attempt ({method}): {username} / {password}");
    }

    private static async Task SendAuthFailureAsync(SshTransport transport, CancellationToken ct)
    {
        byte[] failure = new SshWriter()
            .Byte(SshMessage.UserAuthFailure)
            .NameList("password", "keyboard-interactive")
            .Boolean(false) // partial success
            .ToArray();
        await transport.WritePacketAsync(failure, ct);
    }

    private static async Task SendDisconnectAsync(SshTransport transport, CancellationToken ct)
    {
        try
        {
            byte[] disconnect = new SshWriter()
                .Byte(SshMessage.Disconnect)
                .UInt32(2) // SSH_DISCONNECT_PROTOCOL_ERROR / too many failures
                .String("Too many authentication failures")
                .String("")
                .ToArray();
            await transport.WritePacketAsync(disconnect, ct);
        }
        catch
        {
            // The peer may already be gone; nothing to do.
        }
    }
}

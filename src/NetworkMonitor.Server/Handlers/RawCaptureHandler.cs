using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;

namespace NetworkMonitor.Server.Handlers;

/// <summary>
/// Default handler for binary or unknown services (SMB, RDP, MySQL, VNC, Mongo, …).
/// It stays silent and records whatever the peer sends as a hex dump. Many clients send
/// a recognisable first packet even without a reply, so this still captures useful detail.
/// </summary>
public sealed class RawCaptureHandler : IProtocolHandler
{
    public async Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct)
    {
        var buffer = new byte[8192];
        while (!ct.IsCancellationRequested && !session.RawTruncated)
        {
            int read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (read == 0)
                break;
        }
        session.Note($"Raw capture on port {config.Port}: {session.BytesReceived} bytes, no service emulation.");
    }
}

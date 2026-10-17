using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;

namespace NetworkMonitor.Server.Handlers;

/// <summary>
/// Decodes one TCP connection: reads what the peer sends, optionally plays the part of
/// the real service to draw out more, and records everything into the session. A handler
/// never grants access and never runs anything the peer sends.
/// </summary>
public interface IProtocolHandler
{
    Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct);
}

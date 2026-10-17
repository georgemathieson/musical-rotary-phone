using NetworkMonitor.Server.Capture;

namespace NetworkMonitor.Server.Services;

/// <summary>Persists a finished capture and pushes it live to connected dashboards.</summary>
public interface IConnectionSink
{
    Task PublishAsync(CaptureSession session, CancellationToken ct = default);
}

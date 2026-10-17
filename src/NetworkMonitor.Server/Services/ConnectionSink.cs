using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Data;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Services;

public sealed class ConnectionSink(
    IServiceScopeFactory scopeFactory,
    IHubContext<MonitorHub> hub,
    ILogger<ConnectionSink> logger) : IConnectionSink
{
    public async Task PublishAsync(CaptureSession session, CancellationToken ct = default)
    {
        session.MarkEnded();
        ConnectionEventDto dto = session.ToDto();

        try
        {
            using IServiceScope scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<MonitorDbContext>();

            var record = new ConnectionRecord
            {
                Transport = dto.Transport,
                Port = dto.Port,
                Service = dto.Service,
                RemoteIp = dto.RemoteIp,
                RemotePort = dto.RemotePort,
                StartedAt = dto.StartedAt,
                EndedAt = dto.EndedAt,
                BytesReceived = dto.BytesReceived,
                BytesSent = dto.BytesSent,
                Summary = dto.Summary,
                Notes = string.Join('\n', dto.Notes),
                CredentialsJson = JsonSerializer.Serialize(dto.Credentials),
                HexDump = dto.HexDump,
                RawText = dto.RawText,
            };

            db.Connections.Add(record);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);

            dto = dto with { Id = record.Id };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to persist connection from {Ip}", dto.RemoteIp);
        }

        logger.LogInformation(
            "{Transport} {Ip}:{RemotePort} -> :{Port} {Service} — {Summary}",
            dto.Transport, dto.RemoteIp, dto.RemotePort, dto.Port, dto.Service, dto.Summary);

        try
        {
            await hub.Clients.All.SendAsync(HubContract.ConnectionRecorded, dto, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to broadcast connection event");
        }
    }
}

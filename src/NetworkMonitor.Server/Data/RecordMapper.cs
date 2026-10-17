using System.Text.Json;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Data;

/// <summary>Converts persisted <see cref="ConnectionRecord"/> rows into transport DTOs.</summary>
public static class RecordMapper
{
    public static ConnectionEventDto ToDto(this ConnectionRecord record) => new()
    {
        Id = record.Id,
        Transport = record.Transport,
        Port = record.Port,
        Service = record.Service,
        RemoteIp = record.RemoteIp,
        RemotePort = record.RemotePort,
        StartedAt = record.StartedAt,
        EndedAt = record.EndedAt,
        BytesReceived = record.BytesReceived,
        BytesSent = record.BytesSent,
        Summary = record.Summary,
        Notes = string.IsNullOrEmpty(record.Notes)
            ? new List<string>()
            : record.Notes.Split('\n').ToList(),
        Credentials = DeserializeCredentials(record.CredentialsJson),
        HexDump = record.HexDump,
        RawText = record.RawText,
    };

    private static List<CredentialAttemptDto> DeserializeCredentials(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new List<CredentialAttemptDto>();
        try
        {
            return JsonSerializer.Deserialize<List<CredentialAttemptDto>>(json) ?? new();
        }
        catch
        {
            return new List<CredentialAttemptDto>();
        }
    }
}

using System.ComponentModel.DataAnnotations;

namespace NetworkMonitor.Server.Data;

/// <summary>Persisted form of one observed connection.</summary>
public sealed class ConnectionRecord
{
    public long Id { get; set; }

    [MaxLength(8)]
    public string Transport { get; set; } = "TCP";

    public int Port { get; set; }

    [MaxLength(64)]
    public string Service { get; set; } = "";

    [MaxLength(64)]
    public string RemoteIp { get; set; } = "";

    public int RemotePort { get; set; }

    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? EndedAt { get; set; }

    public long BytesReceived { get; set; }
    public long BytesSent { get; set; }

    [MaxLength(512)]
    public string Summary { get; set; } = "";

    /// <summary>Protocol notes, newline-joined.</summary>
    public string Notes { get; set; } = "";

    /// <summary>Credentials captured, serialised as JSON.</summary>
    public string CredentialsJson { get; set; } = "[]";

    public string HexDump { get; set; } = "";

    public string RawText { get; set; } = "";
}

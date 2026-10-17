namespace NetworkMonitor.Shared;

/// <summary>
/// A single observed connection to one of the monitored ports, sent from the
/// server to the dashboard both as history (REST) and live (SignalR).
/// </summary>
public sealed record ConnectionEventDto
{
    /// <summary>Database id. 0 before the record has been persisted.</summary>
    public long Id { get; init; }

    /// <summary>"TCP" or "UDP".</summary>
    public string Transport { get; init; } = "TCP";

    /// <summary>The local port the peer connected to (e.g. 22).</summary>
    public int Port { get; init; }

    /// <summary>Best guess of the service that normally lives on this port, e.g. "SSH".</summary>
    public string Service { get; init; } = "";

    public string RemoteIp { get; init; } = "";
    public int RemotePort { get; init; }

    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? EndedAt { get; init; }

    public long BytesReceived { get; init; }
    public long BytesSent { get; init; }

    /// <summary>One-line human summary shown in the table (e.g. 'password login root / 123456').</summary>
    public string Summary { get; init; } = "";

    /// <summary>Protocol-level events the handler decoded, newest understanding of what the peer did.</summary>
    public List<string> Notes { get; init; } = new();

    /// <summary>Any credentials the peer offered (SSH/HTTP/FTP/etc.). Logged, never accepted.</summary>
    public List<CredentialAttemptDto> Credentials { get; init; } = new();

    /// <summary>Hex + ASCII dump of the raw bytes the peer sent (capped).</summary>
    public string HexDump { get; init; } = "";

    /// <summary>The raw bytes rendered as text, printable characters only.</summary>
    public string RawText { get; init; } = "";

    public double DurationSeconds =>
        EndedAt is { } end ? Math.Max(0, (end - StartedAt).TotalSeconds) : 0;
}

/// <summary>A username/password (or token) pair a peer tried against a fake service.</summary>
public sealed record CredentialAttemptDto
{
    public string Service { get; init; } = "";
    public string? Username { get; init; }
    public string? Password { get; init; }
    /// <summary>Extra context, e.g. the auth method or where the value came from.</summary>
    public string? Detail { get; init; }
}

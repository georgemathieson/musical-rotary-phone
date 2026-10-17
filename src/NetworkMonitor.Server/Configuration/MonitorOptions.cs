namespace NetworkMonitor.Server.Configuration;

/// <summary>
/// Everything the monitor reads from the <c>Monitor</c> section of appsettings.json.
/// </summary>
public sealed class MonitorOptions
{
    public const string SectionName = "Monitor";

    /// <summary>Address to bind the listeners to. 0.0.0.0 = all interfaces.</summary>
    public string BindAddress { get; set; } = "0.0.0.0";

    /// <summary>TCP ports to listen on.</summary>
    public List<PortConfig> TcpPorts { get; set; } = new();

    /// <summary>UDP ports to listen on.</summary>
    public List<PortConfig> UdpPorts { get; set; } = new();

    public CaptureLimits Limits { get; set; } = new();

    /// <summary>Path to the SQLite database file.</summary>
    public string DatabasePath { get; set; } = "networkmonitor.db";

    /// <summary>How many of the most recent events the dashboard loads on startup.</summary>
    public int HistoryPageSize { get; set; } = 500;
}

public sealed class PortConfig
{
    public int Port { get; set; }

    /// <summary>Service label shown in the UI (e.g. "SSH", "HTTP").</summary>
    public string Service { get; set; } = "";

    /// <summary>
    /// Which handler decodes the connection. One of the names in <see cref="Handlers.HandlerKind"/>
    /// (ssh, http, https, ftp, smtp, pop3, imap, telnet, redis, raw). Empty = pick from the service name.
    /// </summary>
    public string Handler { get; set; } = "";

    /// <summary>Optional banner override for line-based services.</summary>
    public string? Banner { get; set; }
}

public sealed class CaptureLimits
{
    /// <summary>Hard cap on bytes recorded per connection. Protects memory and disk.</summary>
    public int MaxBytesPerConnection { get; set; } = 16 * 1024;

    /// <summary>Close a connection after this many seconds of silence.</summary>
    public int IdleTimeoutSeconds { get; set; } = 30;

    /// <summary>Absolute lifetime cap for a single connection, in seconds.</summary>
    public int MaxConnectionSeconds { get; set; } = 120;

    /// <summary>Maximum simultaneous connections from a single source IP.</summary>
    public int MaxConnectionsPerIp { get; set; } = 20;

    /// <summary>Maximum simultaneous connections across all ports.</summary>
    public int MaxConcurrentConnections { get; set; } = 500;
}

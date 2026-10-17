namespace NetworkMonitor.Shared;

/// <summary>Shared constants for the SignalR hub so the client and server agree on names.</summary>
public static class HubContract
{
    public const string Path = "/hub/monitor";

    /// <summary>Server -&gt; client: a new connection event was recorded.</summary>
    public const string ConnectionRecorded = nameof(ConnectionRecorded);
}

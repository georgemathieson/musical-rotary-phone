using Microsoft.AspNetCore.SignalR;

namespace NetworkMonitor.Server.Services;

/// <summary>Live feed of connection events to the dashboard. Clients only receive.</summary>
public sealed class MonitorHub : Hub
{
}

using System.Net.Http.Json;
using BlazorState;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Client.State;

/// <summary>Lightweight projection of a connection for the live table (keeps the store small).</summary>
public sealed record ConnectionRow(
    long Id,
    DateTimeOffset StartedAt,
    string Transport,
    int Port,
    string Service,
    string RemoteIp,
    int RemotePort,
    long BytesReceived,
    string Summary,
    bool HasCredentials);

public sealed record PortStat(int Port, string Service, int Count);

/// <summary>
/// The single Redux-style store for the dashboard (Blazor-State / MediatR). Components read it
/// through <c>GetState&lt;ConnectionsState&gt;()</c> and change it only by dispatching the actions
/// nested below; the matching handlers are the reducers.
/// </summary>
public partial class ConnectionsState : State<ConnectionsState>
{
    public const int MaxRows = 1000;

    public IReadOnlyList<ConnectionRow> Rows { get; private set; } = Array.Empty<ConnectionRow>();
    public long Total { get; private set; }
    public IReadOnlyList<PortStat> PortStats { get; private set; } = Array.Empty<PortStat>();
    public string PortLabel { get; private set; } = "…";

    public bool Live { get; private set; }
    public bool Paused { get; private set; }

    public int? PortFilter { get; private set; }
    public string IpFilter { get; private set; } = "";
    public string TextFilter { get; private set; } = "";

    public long? SelectedId { get; private set; }
    public ConnectionEventDto? SelectedDetail { get; private set; }

    public override void Initialize()
    {
        // Defaults are set via the property initializers above.
    }

    /// <summary>Selector: the rows that pass the current filters.</summary>
    public IEnumerable<ConnectionRow> FilteredRows => Rows.Where(r =>
        (PortFilter is null || r.Port == PortFilter) &&
        (IpFilter.Length == 0 || r.RemoteIp.Contains(IpFilter, StringComparison.OrdinalIgnoreCase)) &&
        (TextFilter.Length == 0 ||
            r.Summary.Contains(TextFilter, StringComparison.OrdinalIgnoreCase) ||
            r.Service.Contains(TextFilter, StringComparison.OrdinalIgnoreCase)));

    private static ConnectionRow ToRow(ConnectionEventDto d) => new(
        d.Id, d.StartedAt, d.Transport, d.Port, d.Service, d.RemoteIp, d.RemotePort,
        d.BytesReceived, d.Summary, d.Credentials.Count > 0);
}

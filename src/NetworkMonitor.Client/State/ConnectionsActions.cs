using System.Net.Http.Json;
using BlazorState;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Client.State;

// Actions (MediatR requests) and their handlers (the reducers). Blazor-State requires both to be
// nested inside the state class, so everything here is a partial of ConnectionsState.
public partial class ConnectionsState
{
    // ---- Load initial data (effect: fetches config, history and stats) --------------------
    public sealed class InitializeAction : IAction { }

    public sealed class InitializeHandler(IStore store, HttpClient http)
        : ActionHandler<InitializeAction>(store)
    {
        private ConnectionsState State => Store.GetState<ConnectionsState>();

        public override async Task Handle(InitializeAction action, CancellationToken ct)
        {
            try
            {
                var config = await http.GetFromJsonAsync<ConfigResponse>("api/config", ct);
                if (config is not null)
                {
                    var ports = config.TcpPorts.Select(p => p.Port)
                        .Concat(config.UdpPorts.Select(p => p.Port))
                        .OrderBy(p => p);
                    State.PortLabel = string.Join(", ", ports);
                }
            }
            catch { State.PortLabel = "(unavailable)"; }

            await LoadConnectionsHandler.LoadAsync(State, http, ct);
        }
    }

    // ---- Reload the table from the server --------------------------------------------------
    public sealed class LoadConnectionsAction : IAction { }

    public sealed class LoadConnectionsHandler(IStore store, HttpClient http)
        : ActionHandler<LoadConnectionsAction>(store)
    {
        private ConnectionsState State => Store.GetState<ConnectionsState>();

        public override Task Handle(LoadConnectionsAction action, CancellationToken ct) =>
            LoadAsync(State, http, ct);

        internal static async Task LoadAsync(ConnectionsState state, HttpClient http, CancellationToken ct)
        {
            try
            {
                var rows = await http.GetFromJsonAsync<List<ConnectionEventDto>>("api/connections?take=1000", ct);
                state.Rows = rows is null ? Array.Empty<ConnectionRow>() : rows.Select(ToRow).ToList();

                var stats = await http.GetFromJsonAsync<StatsResponse>("api/stats", ct);
                if (stats is not null)
                {
                    state.Total = stats.Total;
                    state.PortStats = stats.Ports;
                }
            }
            catch { /* server may still be starting */ }
        }
    }

    // ---- A new connection arrived live over SignalR (pure reducer) -------------------------
    public sealed class ConnectionReceivedAction : IAction
    {
        public required ConnectionEventDto Dto { get; init; }
    }

    public sealed class ConnectionReceivedHandler(IStore store)
        : ActionHandler<ConnectionReceivedAction>(store)
    {
        private ConnectionsState State => Store.GetState<ConnectionsState>();

        public override Task Handle(ConnectionReceivedAction action, CancellationToken ct)
        {
            if (State.Paused)
                return Task.CompletedTask;

            ConnectionEventDto dto = action.Dto;
            State.Rows = new[] { ToRow(dto) }.Concat(State.Rows).Take(MaxRows).ToList();
            State.Total++;

            var stats = State.PortStats.ToList();
            int idx = stats.FindIndex(s => s.Port == dto.Port);
            stats[idx >= 0 ? idx : stats.Count] = idx >= 0
                ? stats[idx] with { Count = stats[idx].Count + 1 }
                : new PortStat(dto.Port, dto.Service, 1);
            State.PortStats = stats;

            return Task.CompletedTask;
        }
    }

    // ---- Select a row (effect: fetches the full detail) ------------------------------------
    public sealed class SelectConnectionAction : IAction
    {
        public required long Id { get; init; }
    }

    public sealed class SelectConnectionHandler(IStore store, HttpClient http)
        : ActionHandler<SelectConnectionAction>(store)
    {
        private ConnectionsState State => Store.GetState<ConnectionsState>();

        public override async Task Handle(SelectConnectionAction action, CancellationToken ct)
        {
            State.SelectedId = action.Id;
            try
            {
                State.SelectedDetail = await http.GetFromJsonAsync<ConnectionEventDto>(
                    $"api/connections/{action.Id}", ct);
            }
            catch { State.SelectedDetail = null; }
        }
    }

    public sealed class ClearSelectionAction : IAction { }

    public sealed class ClearSelectionHandler(IStore store) : ActionHandler<ClearSelectionAction>(store)
    {
        public override Task Handle(ClearSelectionAction action, CancellationToken ct)
        {
            ConnectionsState state = Store.GetState<ConnectionsState>();
            state.SelectedId = null;
            state.SelectedDetail = null;
            return Task.CompletedTask;
        }
    }

    // ---- Simple state setters (pure reducers) ----------------------------------------------
    public sealed class SetLiveAction : IAction { public required bool Live { get; init; } }

    public sealed class SetLiveHandler(IStore store) : ActionHandler<SetLiveAction>(store)
    {
        public override Task Handle(SetLiveAction action, CancellationToken ct)
        {
            Store.GetState<ConnectionsState>().Live = action.Live;
            return Task.CompletedTask;
        }
    }

    public sealed class SetPausedAction : IAction { public required bool Paused { get; init; } }

    public sealed class SetPausedHandler(IStore store) : ActionHandler<SetPausedAction>(store)
    {
        public override Task Handle(SetPausedAction action, CancellationToken ct)
        {
            Store.GetState<ConnectionsState>().Paused = action.Paused;
            return Task.CompletedTask;
        }
    }

    public sealed class TogglePortFilterAction : IAction { public required int Port { get; init; } }

    public sealed class TogglePortFilterHandler(IStore store) : ActionHandler<TogglePortFilterAction>(store)
    {
        public override Task Handle(TogglePortFilterAction action, CancellationToken ct)
        {
            ConnectionsState state = Store.GetState<ConnectionsState>();
            state.PortFilter = state.PortFilter == action.Port ? null : action.Port;
            return Task.CompletedTask;
        }
    }

    public sealed class SetIpFilterAction : IAction { public required string Value { get; init; } }

    public sealed class SetIpFilterHandler(IStore store) : ActionHandler<SetIpFilterAction>(store)
    {
        public override Task Handle(SetIpFilterAction action, CancellationToken ct)
        {
            Store.GetState<ConnectionsState>().IpFilter = action.Value;
            return Task.CompletedTask;
        }
    }

    public sealed class SetTextFilterAction : IAction { public required string Value { get; init; } }

    public sealed class SetTextFilterHandler(IStore store) : ActionHandler<SetTextFilterAction>(store)
    {
        public override Task Handle(SetTextFilterAction action, CancellationToken ct)
        {
            Store.GetState<ConnectionsState>().TextFilter = action.Value;
            return Task.CompletedTask;
        }
    }

    public sealed class ClearFiltersAction : IAction { }

    public sealed class ClearFiltersHandler(IStore store) : ActionHandler<ClearFiltersAction>(store)
    {
        public override Task Handle(ClearFiltersAction action, CancellationToken ct)
        {
            ConnectionsState state = Store.GetState<ConnectionsState>();
            state.PortFilter = null;
            state.IpFilter = "";
            state.TextFilter = "";
            return Task.CompletedTask;
        }
    }

    // ---- JSON shapes returned by the REST API ----------------------------------------------
    private sealed class ConfigResponse
    {
        public List<PortEntry> TcpPorts { get; set; } = new();
        public List<PortEntry> UdpPorts { get; set; } = new();
    }

    private sealed class PortEntry
    {
        public int Port { get; set; }
        public string Service { get; set; } = "";
    }

    private sealed class StatsResponse
    {
        public long Total { get; set; }
        public List<PortStat> Ports { get; set; } = new();
    }
}

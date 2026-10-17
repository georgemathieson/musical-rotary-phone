using System.Collections.Concurrent;
using System.Net;
using NetworkMonitor.Server.Configuration;

namespace NetworkMonitor.Server.Services;

/// <summary>
/// Enforces the safety caps on concurrent TCP connections so a flood cannot exhaust memory:
/// a global maximum and a per-source-IP maximum.
/// </summary>
public sealed class ConnectionLimiter(CaptureLimits limits)
{
    private readonly ConcurrentDictionary<string, int> _perIp = new();
    private int _total;

    public bool TryAcquire(IPAddress address)
    {
        if (Interlocked.Increment(ref _total) > limits.MaxConcurrentConnections)
        {
            Interlocked.Decrement(ref _total);
            return false;
        }

        string key = address.ToString();
        int afterIncrement = _perIp.AddOrUpdate(key, 1, (_, current) => current + 1);
        if (afterIncrement > limits.MaxConnectionsPerIp)
        {
            Release(address);
            return false;
        }
        return true;
    }

    public void Release(IPAddress address)
    {
        Interlocked.Decrement(ref _total);
        string key = address.ToString();
        _perIp.AddOrUpdate(key, 0, (_, current) => current - 1);
        _perIp.TryRemove(KeyValuePair.Create(key, 0));
    }
}

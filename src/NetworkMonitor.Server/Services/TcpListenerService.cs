using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Server.Handlers;

namespace NetworkMonitor.Server.Services;

/// <summary>Binds every configured TCP port and dispatches each accepted connection to a handler.</summary>
public sealed class TcpListenerService(
    IOptions<MonitorOptions> options,
    ProtocolHandlerResolver resolver,
    IConnectionSink sink,
    ConnectionLimiter limiter,
    ILogger<TcpListenerService> logger) : BackgroundService
{
    private readonly MonitorOptions _options = options.Value;
    private readonly List<TcpListener> _listeners = new();

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        IPAddress bind = IPAddress.TryParse(_options.BindAddress, out IPAddress? parsed) ? parsed : IPAddress.Any;
        var loops = new List<Task>();

        foreach (PortConfig port in _options.TcpPorts)
        {
            TcpListener listener;
            try
            {
                listener = new TcpListener(bind, port.Port);
                listener.Start();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Could not listen on TCP port {Port} ({Service})", port.Port, port.Service);
                continue;
            }

            _listeners.Add(listener);
            logger.LogInformation("Listening on TCP {Bind}:{Port} ({Service})", bind, port.Port, port.Service);
            loops.Add(AcceptLoopAsync(listener, port, stoppingToken));
        }

        return Task.WhenAll(loops);
    }

    private async Task AcceptLoopAsync(TcpListener listener, PortConfig port, CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Accept failed on port {Port}", port.Port);
                continue;
            }

            _ = HandleClientAsync(client, port, stoppingToken);
        }
    }

    private async Task HandleClientAsync(TcpClient client, PortConfig port, CancellationToken stoppingToken)
    {
        var remote = (IPEndPoint)client.Client.RemoteEndPoint!;

        if (!limiter.TryAcquire(remote.Address))
        {
            logger.LogWarning("Rejected connection from {Ip} (connection cap reached)", remote.Address);
            client.Close();
            return;
        }

        var session = new CaptureSession("TCP", port.Port, port.Service, remote, _options.Limits.MaxBytesPerConnection);

        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        lifetime.CancelAfter(TimeSpan.FromSeconds(_options.Limits.MaxConnectionSeconds));

        try
        {
            client.NoDelay = true;
            using NetworkStream raw = client.GetStream();
            var monitored = new MonitoredStream(raw, session, TimeSpan.FromSeconds(_options.Limits.IdleTimeoutSeconds));
            IProtocolHandler handler = resolver.Resolve(port);
            await handler.HandleAsync(session, monitored, port, lifetime.Token);
        }
        catch (OperationCanceledException)
        {
            session.Note("Connection closed (idle or lifetime limit).");
        }
        catch (Exception ex)
        {
            session.Note($"Handler error: {ex.Message}");
            logger.LogDebug(ex, "Handler error on port {Port} from {Ip}", port.Port, remote.Address);
        }
        finally
        {
            limiter.Release(remote.Address);
            try { client.Close(); } catch { /* already closed */ }
            await sink.PublishAsync(session, CancellationToken.None);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        foreach (TcpListener listener in _listeners)
        {
            try { listener.Stop(); } catch { /* ignore */ }
        }
        await base.StopAsync(cancellationToken);
    }
}

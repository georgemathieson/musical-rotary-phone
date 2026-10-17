using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Options;
using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;

namespace NetworkMonitor.Server.Services;

/// <summary>
/// Binds configured UDP ports and records every datagram received. UDP is connectionless,
/// so each datagram is logged as its own event. DNS queries get their requested name decoded.
/// </summary>
public sealed class UdpListenerService(
    IOptions<MonitorOptions> options,
    IConnectionSink sink,
    ILogger<UdpListenerService> logger) : BackgroundService
{
    private readonly MonitorOptions _options = options.Value;
    private readonly List<UdpClient> _clients = new();

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        IPAddress bind = IPAddress.TryParse(_options.BindAddress, out IPAddress? parsed) ? parsed : IPAddress.Any;
        var loops = new List<Task>();

        foreach (PortConfig port in _options.UdpPorts)
        {
            UdpClient udp;
            try
            {
                udp = new UdpClient(new IPEndPoint(bind, port.Port));
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Could not listen on UDP port {Port} ({Service})", port.Port, port.Service);
                continue;
            }

            _clients.Add(udp);
            logger.LogInformation("Listening on UDP {Bind}:{Port} ({Service})", bind, port.Port, port.Service);
            loops.Add(ReceiveLoopAsync(udp, port, stoppingToken));
        }

        return Task.WhenAll(loops);
    }

    private async Task ReceiveLoopAsync(UdpClient udp, PortConfig port, CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await udp.ReceiveAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "UDP receive failed on port {Port}", port.Port);
                continue;
            }

            var session = new CaptureSession("UDP", port.Port, port.Service, result.RemoteEndPoint,
                _options.Limits.MaxBytesPerConnection);
            session.RecordInbound(result.Buffer);
            session.Note($"UDP datagram: {result.Buffer.Length} bytes to {port.Service} ({port.Port}).");

            if (port.Port == 53 && TryDecodeDnsQuery(result.Buffer, out string name))
            {
                session.Note($"DNS query for: {name}");
                session.Summary = $"DNS query {name}";
            }

            await sink.PublishAsync(session, CancellationToken.None);
        }
    }

    /// <summary>Extracts the first question name from a DNS query packet, if it looks like one.</summary>
    private static bool TryDecodeDnsQuery(byte[] data, out string name)
    {
        name = "";
        if (data.Length < 13)
            return false;

        try
        {
            int pos = 12; // skip the 12-byte header
            var labels = new List<string>();
            while (pos < data.Length)
            {
                int len = data[pos++];
                if (len == 0)
                    break;
                if (len > 63 || pos + len > data.Length)
                    return false;
                labels.Add(Encoding.ASCII.GetString(data, pos, len));
                pos += len;
            }
            name = string.Join('.', labels);
            return name.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        foreach (UdpClient client in _clients)
        {
            try { client.Dispose(); } catch { /* ignore */ }
        }
        await base.StopAsync(cancellationToken);
    }
}

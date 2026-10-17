using System.Net.Security;
using System.Security.Authentication;
using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Server.Services;

namespace NetworkMonitor.Server.Handlers;

/// <summary>
/// Terminates TLS with a self-signed certificate, records the requested SNI host and the
/// negotiated cipher, then decodes the inner request with the HTTP handler.
/// </summary>
public sealed class TlsHandler(CertificateProvider certificates, HttpHandler http) : IProtocolHandler
{
    public async Task HandleAsync(CaptureSession session, Stream stream, PortConfig config, CancellationToken ct)
    {
        var ssl = new SslStream(stream, leaveInnerStreamOpen: true);
        var options = new SslServerAuthenticationOptions
        {
            ServerCertificateSelectionCallback = (_, host) =>
            {
                if (!string.IsNullOrEmpty(host))
                {
                    session.Note($"TLS SNI host: {host}");
                    session.Summary = $"TLS ClientHello for {host}";
                }
                return certificates.Certificate;
            },
            ClientCertificateRequired = false,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        };

        try
        {
            await ssl.AuthenticateAsServerAsync(options, ct);
        }
        catch (Exception ex)
        {
            session.Note($"TLS handshake did not complete: {ex.Message}");
            return;
        }

        session.Note($"TLS established: {ssl.SslProtocol}, cipher {ssl.NegotiatedCipherSuite}");
        await http.ProcessAsync(session, ssl, "https", ct);
    }
}

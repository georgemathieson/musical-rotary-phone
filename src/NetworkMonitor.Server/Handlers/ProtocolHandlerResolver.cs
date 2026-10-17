using NetworkMonitor.Server.Configuration;

namespace NetworkMonitor.Server.Handlers;

/// <summary>Chooses the handler for a port from its explicit <c>Handler</c> or its service name.</summary>
public sealed class ProtocolHandlerResolver(IServiceProvider services)
{
    public IProtocolHandler Resolve(PortConfig config)
    {
        string key = (string.IsNullOrWhiteSpace(config.Handler) ? config.Service : config.Handler)
            .Trim()
            .ToLowerInvariant();

        return key switch
        {
            "ssh" => services.GetRequiredService<SshHandler>(),
            "http" or "http-proxy" or "http-alt" => services.GetRequiredService<HttpHandler>(),
            "https" or "https-alt" => services.GetRequiredService<TlsHandler>(),
            "ftp" => services.GetRequiredService<FtpHandler>(),
            "smtp" or "submission" => services.GetRequiredService<SmtpHandler>(),
            "pop3" => services.GetRequiredService<Pop3Handler>(),
            "imap" => services.GetRequiredService<ImapHandler>(),
            "telnet" => services.GetRequiredService<TelnetHandler>(),
            "redis" => services.GetRequiredService<RedisHandler>(),
            _ => services.GetRequiredService<RawCaptureHandler>(),
        };
    }
}

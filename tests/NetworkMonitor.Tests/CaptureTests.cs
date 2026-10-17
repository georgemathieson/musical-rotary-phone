using System.Net;
using NetworkMonitor.Server.Capture;
using NetworkMonitor.Server.Configuration;
using NetworkMonitor.Server.Services;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Tests;

public class CaptureSessionTests
{
    private static CaptureSession NewSession(int cap = 1024) =>
        new("TCP", 22, "SSH", new IPEndPoint(IPAddress.Parse("10.0.0.5"), 4321), cap);

    [Fact]
    public void ToDto_CarriesCoreFields()
    {
        var session = NewSession();
        session.RecordInbound(new byte[] { 1, 2, 3, 4 });
        session.RecordOutbound(new byte[] { 9 });
        session.MarkEnded();

        ConnectionEventDto dto = session.ToDto(7);

        Assert.Equal(7, dto.Id);
        Assert.Equal("TCP", dto.Transport);
        Assert.Equal(22, dto.Port);
        Assert.Equal("10.0.0.5", dto.RemoteIp);
        Assert.Equal(4321, dto.RemotePort);
        Assert.Equal(4, dto.BytesReceived);
        Assert.Equal(1, dto.BytesSent);
    }

    [Fact]
    public void RecordInbound_TruncatesAtCapAndCountsAllBytes()
    {
        var session = NewSession(cap: 8);
        session.RecordInbound(new byte[10]); // more than the cap

        Assert.True(session.RawTruncated);
        Assert.Equal(10, session.ToDto().BytesReceived);        // full count preserved
        Assert.Contains("truncated", string.Join(" ", session.ToDto().Notes));
    }

    [Fact]
    public void DefaultSummary_UsesFirstCredential()
    {
        var session = NewSession();
        session.AddCredential(new CredentialAttemptDto { Service = "SSH", Username = "root", Password = "toor" });

        Assert.Equal("login root / toor", session.ToDto().Summary);
    }

    [Fact]
    public void ExplicitSummary_WinsOverDefault()
    {
        var session = NewSession();
        session.RecordInbound(new byte[] { 1 });
        session.Summary = "custom";

        Assert.Equal("custom", session.ToDto().Summary);
    }
}

public class ConnectionLimiterTests
{
    [Fact]
    public void EnforcesPerIpCap()
    {
        var limiter = new ConnectionLimiter(new CaptureLimits { MaxConnectionsPerIp = 2, MaxConcurrentConnections = 100 });
        var ip = IPAddress.Parse("1.2.3.4");

        Assert.True(limiter.TryAcquire(ip));
        Assert.True(limiter.TryAcquire(ip));
        Assert.False(limiter.TryAcquire(ip));   // third from same IP rejected

        limiter.Release(ip);
        Assert.True(limiter.TryAcquire(ip));     // slot freed
    }

    [Fact]
    public void EnforcesGlobalCap()
    {
        var limiter = new ConnectionLimiter(new CaptureLimits { MaxConnectionsPerIp = 100, MaxConcurrentConnections = 2 });

        Assert.True(limiter.TryAcquire(IPAddress.Parse("1.1.1.1")));
        Assert.True(limiter.TryAcquire(IPAddress.Parse("2.2.2.2")));
        Assert.False(limiter.TryAcquire(IPAddress.Parse("3.3.3.3")));   // global cap reached
    }
}

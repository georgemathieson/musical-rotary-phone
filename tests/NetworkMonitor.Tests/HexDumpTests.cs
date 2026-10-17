using System.Text;
using NetworkMonitor.Server.Capture;

namespace NetworkMonitor.Tests;

public class HexDumpTests
{
    [Fact]
    public void Format_ProducesOffsetHexAndAscii()
    {
        byte[] data = Encoding.ASCII.GetBytes("GET / HTTP/1.1");
        string dump = HexDump.Format(data);

        Assert.StartsWith("00000000  ", dump);
        Assert.Contains("47 45 54", dump);          // 'G' 'E' 'T'
        Assert.Contains("|GET / HTTP/1.1|", dump);
    }

    [Fact]
    public void Format_EmptyInput_ReturnsEmpty()
    {
        Assert.Equal("", HexDump.Format(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void AsText_ReplacesNonPrintableWithDot()
    {
        byte[] data = { 0x00, (byte)'h', (byte)'i', 0x01, 0xff };
        Assert.Equal(".hi..", HexDump.AsText(data));
    }

    [Fact]
    public void AsText_KeepsCommonWhitespace()
    {
        byte[] data = Encoding.ASCII.GetBytes("a\tb\r\nc");
        Assert.Equal("a\tb\r\nc", HexDump.AsText(data));
    }
}

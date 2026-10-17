using System.Text.Json;
using NetworkMonitor.Server.Data;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Tests;

public class RecordMapperTests
{
    [Fact]
    public void ToDto_SplitsNotesAndDeserialisesCredentials()
    {
        var credentials = new List<CredentialAttemptDto>
        {
            new() { Service = "SSH", Username = "root", Password = "hunter2", Detail = "password" }
        };
        var record = new ConnectionRecord
        {
            Id = 3,
            Transport = "TCP",
            Port = 22,
            Service = "SSH",
            RemoteIp = "8.8.8.8",
            RemotePort = 1234,
            Summary = "SSH password login root / hunter2",
            Notes = "line one\nline two",
            CredentialsJson = JsonSerializer.Serialize(credentials),
            HexDump = "00000000  ...",
            RawText = "raw",
        };

        ConnectionEventDto dto = record.ToDto();

        Assert.Equal(3, dto.Id);
        Assert.Equal(new[] { "line one", "line two" }, dto.Notes);
        Assert.Single(dto.Credentials);
        Assert.Equal("root", dto.Credentials[0].Username);
        Assert.Equal("hunter2", dto.Credentials[0].Password);
    }

    [Fact]
    public void ToDto_ToleratesEmptyNotesAndBadJson()
    {
        var record = new ConnectionRecord { Notes = "", CredentialsJson = "not-json" };
        ConnectionEventDto dto = record.ToDto();

        Assert.Empty(dto.Notes);
        Assert.Empty(dto.Credentials);
    }
}

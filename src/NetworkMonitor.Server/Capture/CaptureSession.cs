using System.Net;
using NetworkMonitor.Shared;

namespace NetworkMonitor.Server.Capture;

/// <summary>
/// Accumulates everything observed during a single connection. Handlers write to it;
/// at the end it is turned into a <see cref="ConnectionEventDto"/> and persisted.
/// </summary>
public sealed class CaptureSession
{
    private readonly int _maxBytes;
    private readonly List<byte> _rawInbound = new();
    private readonly List<string> _notes = new();
    private readonly List<CredentialAttemptDto> _credentials = new();
    private readonly object _lock = new();

    public CaptureSession(string transport, int port, string service, IPEndPoint remote, int maxBytes)
    {
        Transport = transport;
        Port = port;
        Service = service;
        RemoteIp = remote.Address.ToString();
        RemotePort = remote.Port;
        StartedAt = DateTimeOffset.UtcNow;
        _maxBytes = maxBytes;
    }

    public string Transport { get; }
    public int Port { get; }
    public string Service { get; set; }
    public string RemoteIp { get; }
    public int RemotePort { get; }
    public DateTimeOffset StartedAt { get; }
    public DateTimeOffset? EndedAt { get; private set; }

    public long BytesReceived { get; private set; }
    public long BytesSent { get; private set; }

    public string Summary { get; set; } = "";

    /// <summary>True once the raw-byte buffer has hit the cap and is no longer growing.</summary>
    public bool RawTruncated { get; private set; }

    /// <summary>Records inbound bytes for the hex dump (capped) and the received-byte counter.</summary>
    public void RecordInbound(ReadOnlySpan<byte> data)
    {
        lock (_lock)
        {
            BytesReceived += data.Length;
            int room = _maxBytes - _rawInbound.Count;
            if (room <= 0)
            {
                RawTruncated = true;
                return;
            }
            if (data.Length > room)
            {
                _rawInbound.AddRange(data[..room].ToArray());
                RawTruncated = true;
            }
            else
            {
                _rawInbound.AddRange(data.ToArray());
            }
        }
    }

    /// <summary>Records that bytes were sent back to the peer (banners, prompts, rejections).</summary>
    public void RecordOutbound(ReadOnlySpan<byte> data)
    {
        lock (_lock)
            BytesSent += data.Length;
    }

    /// <summary>Adds a decoded, human-readable protocol event.</summary>
    public void Note(string note)
    {
        lock (_lock)
            _notes.Add(note);
    }

    public void AddCredential(CredentialAttemptDto credential)
    {
        lock (_lock)
            _credentials.Add(credential);
    }

    public void MarkEnded() => EndedAt ??= DateTimeOffset.UtcNow;

    public IReadOnlyList<CredentialAttemptDto> Credentials
    {
        get { lock (_lock) return _credentials.ToArray(); }
    }

    public ConnectionEventDto ToDto(long id = 0)
    {
        lock (_lock)
        {
            byte[] raw = _rawInbound.ToArray();
            var notes = new List<string>(_notes);
            if (RawTruncated)
                notes.Add($"(capture truncated at {_maxBytes} bytes)");

            return new ConnectionEventDto
            {
                Id = id,
                Transport = Transport,
                Port = Port,
                Service = Service,
                RemoteIp = RemoteIp,
                RemotePort = RemotePort,
                StartedAt = StartedAt,
                EndedAt = EndedAt,
                BytesReceived = BytesReceived,
                BytesSent = BytesSent,
                Summary = string.IsNullOrEmpty(Summary) ? DefaultSummary() : Summary,
                Notes = notes,
                Credentials = new List<CredentialAttemptDto>(_credentials),
                HexDump = HexDump.Format(raw),
                RawText = HexDump.AsText(raw),
            };
        }
    }

    private string DefaultSummary()
    {
        if (_credentials.Count > 0)
        {
            var c = _credentials[0];
            return $"login {c.Username ?? "?"} / {c.Password ?? "?"}";
        }
        return BytesReceived > 0
            ? $"{BytesReceived} bytes to {Service} ({Port})"
            : $"connected to {Service} ({Port}), sent nothing";
    }
}

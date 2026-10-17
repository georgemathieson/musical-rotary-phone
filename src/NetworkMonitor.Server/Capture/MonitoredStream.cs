namespace NetworkMonitor.Server.Capture;

/// <summary>
/// Wraps the raw socket stream so every byte in and out is recorded into the
/// <see cref="CaptureSession"/>, an idle read returns end-of-stream instead of hanging,
/// and reads stop once the capture cap is reached.
/// </summary>
public sealed class MonitoredStream : Stream
{
    private readonly Stream _inner;
    private readonly CaptureSession _session;
    private readonly TimeSpan _idleTimeout;

    public MonitoredStream(Stream inner, CaptureSession session, TimeSpan idleTimeout)
    {
        _inner = inner;
        _session = session;
        _idleTimeout = idleTimeout;
    }

    /// <summary>Set when a read returned 0 because the peer went idle, not because it closed.</summary>
    public bool TimedOut { get; private set; }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
        idle.CancelAfter(_idleTimeout);
        try
        {
            int read = await _inner.ReadAsync(buffer, idle.Token).ConfigureAwait(false);
            if (read > 0)
                _session.RecordInbound(buffer.Span[..read]);
            return read;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // The idle timer fired, not the caller's token: treat as end-of-stream.
            TimedOut = true;
            return 0;
        }
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        _session.RecordOutbound(buffer.Span);
        await _inner.WriteAsync(buffer, ct).ConfigureAwait(false);
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
    public override void Flush() => _inner.Flush();

    public override bool CanRead => _inner.CanRead;
    public override bool CanWrite => _inner.CanWrite;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}

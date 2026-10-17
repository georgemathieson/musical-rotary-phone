using System.Buffers.Binary;
using System.Numerics;
using System.Text;

namespace NetworkMonitor.Server.Ssh;

/// <summary>Writes the SSH binary data types (RFC 4251 §5): byte, uint32, string, mpint, name-list.</summary>
internal sealed class SshWriter
{
    private readonly List<byte> _buffer = new();

    public SshWriter Byte(byte value)
    {
        _buffer.Add(value);
        return this;
    }

    public SshWriter Boolean(bool value) => Byte(value ? (byte)1 : (byte)0);

    public SshWriter UInt32(uint value)
    {
        Span<byte> tmp = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(tmp, value);
        _buffer.AddRange(tmp.ToArray());
        return this;
    }

    /// <summary>Writes a length-prefixed byte string.</summary>
    public SshWriter String(ReadOnlySpan<byte> value)
    {
        UInt32((uint)value.Length);
        _buffer.AddRange(value.ToArray());
        return this;
    }

    public SshWriter String(string value) => String(Encoding.UTF8.GetBytes(value));

    public SshWriter NameList(params string[] names) => String(string.Join(',', names));

    /// <summary>Writes a multiple-precision integer in SSH mpint form (RFC 4251 §5).</summary>
    public SshWriter MpInt(BigInteger value)
    {
        if (value.Sign == 0)
            return UInt32(0);

        // Big-endian, unsigned, with a leading 0x00 when the high bit is set.
        byte[] be = value.ToByteArray(isUnsigned: false, isBigEndian: true);
        // BigInteger gives two's-complement; for positive values this already prepends 0x00
        // when needed, so it is exactly the mpint body.
        return String(be);
    }

    /// <summary>Appends already-encoded bytes verbatim (e.g. a pre-built blob).</summary>
    public SshWriter Raw(ReadOnlySpan<byte> value)
    {
        _buffer.AddRange(value.ToArray());
        return this;
    }

    public byte[] ToArray() => _buffer.ToArray();
}

/// <summary>Reads the SSH binary data types from a payload buffer.</summary>
internal ref struct SshReader(ReadOnlySpan<byte> data)
{
    private ReadOnlySpan<byte> _data = data;
    private int _pos = 0;

    public readonly bool End => _pos >= _data.Length;

    public byte Byte() => _data[_pos++];

    public bool Boolean() => Byte() != 0;

    public uint UInt32()
    {
        uint v = BinaryPrimitives.ReadUInt32BigEndian(_data.Slice(_pos, 4));
        _pos += 4;
        return v;
    }

    public byte[] String()
    {
        int len = checked((int)UInt32());
        byte[] result = _data.Slice(_pos, len).ToArray();
        _pos += len;
        return result;
    }

    public string Utf8String() => Encoding.UTF8.GetString(String());

    public BigInteger MpInt()
    {
        byte[] bytes = String();
        return bytes.Length == 0 ? BigInteger.Zero : new BigInteger(bytes, isUnsigned: false, isBigEndian: true);
    }

    public void Skip(int count) => _pos += count;
}

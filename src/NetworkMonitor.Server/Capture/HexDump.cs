using System.Text;

namespace NetworkMonitor.Server.Capture;

/// <summary>Renders byte buffers as a classic offset / hex / ASCII dump.</summary>
public static class HexDump
{
    public static string Format(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return "";

        var sb = new StringBuilder();
        for (int offset = 0; offset < data.Length; offset += 16)
        {
            int lineLen = Math.Min(16, data.Length - offset);
            sb.Append(offset.ToString("x8")).Append("  ");

            for (int i = 0; i < 16; i++)
            {
                if (i < lineLen)
                    sb.Append(data[offset + i].ToString("x2")).Append(' ');
                else
                    sb.Append("   ");
                if (i == 7)
                    sb.Append(' ');
            }

            sb.Append(" |");
            for (int i = 0; i < lineLen; i++)
            {
                byte b = data[offset + i];
                sb.Append(b is >= 0x20 and < 0x7f ? (char)b : '.');
            }
            sb.Append("|\n");
        }
        return sb.ToString();
    }

    /// <summary>Renders bytes as text, keeping printable ASCII and common whitespace, else '.'.</summary>
    public static string AsText(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return "";

        var sb = new StringBuilder(data.Length);
        foreach (byte b in data)
        {
            if (b is (byte)'\n' or (byte)'\r' or (byte)'\t' || (b is >= 0x20 and < 0x7f))
                sb.Append((char)b);
            else
                sb.Append('.');
        }
        return sb.ToString();
    }
}

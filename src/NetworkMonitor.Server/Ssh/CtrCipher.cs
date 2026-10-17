using System.Security.Cryptography;

namespace NetworkMonitor.Server.Ssh;

/// <summary>
/// AES in counter (CTR) mode, as SSH uses it (aes128-ctr / aes256-ctr). The counter is a
/// 128-bit big-endian value that advances once per 16-byte block across the whole session.
/// </summary>
internal sealed class CtrCipher : IDisposable
{
    private const int BlockSize = 16;
    private readonly ICryptoTransform _ecb;
    private readonly byte[] _counter;
    private readonly byte[] _keystream = new byte[BlockSize];

    public CtrCipher(byte[] key, byte[] iv)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        _ecb = aes.CreateEncryptor();
        _counter = (byte[])iv.Clone();
    }

    /// <summary>XORs <paramref name="data"/> in place with the keystream. Length must be a block multiple.</summary>
    public void Process(Span<byte> data)
    {
        for (int offset = 0; offset < data.Length; offset += BlockSize)
        {
            _ecb.TransformBlock(_counter, 0, BlockSize, _keystream, 0);
            for (int i = 0; i < BlockSize; i++)
                data[offset + i] ^= _keystream[i];
            IncrementCounter();
        }
    }

    private void IncrementCounter()
    {
        for (int i = BlockSize - 1; i >= 0; i--)
        {
            if (++_counter[i] != 0)
                break;
        }
    }

    public void Dispose() => _ecb.Dispose();
}

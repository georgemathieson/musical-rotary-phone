using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using NetworkMonitor.Server.Services;

namespace NetworkMonitor.Server.Ssh;

/// <summary>
/// Implements just enough of the SSH transport layer (RFC 4253) to complete a key exchange
/// with a real client and then exchange encrypted packets. The point is to let the client
/// reach the authentication stage so its login attempt can be observed; no session is ever
/// granted.
/// </summary>
internal sealed class SshTransport : IDisposable
{
    private static readonly string[] OfferedKex = { "diffie-hellman-group14-sha256" };
    private static readonly string[] OfferedHostKey = { "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa" };
    private static readonly string[] OfferedCipher = { "aes256-ctr", "aes128-ctr" };
    private static readonly string[] OfferedMac = { "hmac-sha2-256" };
    private static readonly string[] OfferedComp = { "none" };

    private readonly Stream _stream;
    private readonly SshHostKeyProvider _hostKey;
    private readonly Action<string> _note;

    private uint _readSeq, _writeSeq;
    private CtrCipher? _readCipher, _writeCipher;
    private byte[] _readMacKey = Array.Empty<byte>();
    private byte[] _writeMacKey = Array.Empty<byte>();
    private bool _readEncrypted, _writeEncrypted;

    private string _hostKeyAlgorithm = "rsa-sha2-512";
    private string _cipherC2S = "aes256-ctr";
    private string _cipherS2C = "aes256-ctr";
    private int _readCipherBlock = 8;

    public SshTransport(Stream stream, SshHostKeyProvider hostKey, Action<string> note)
    {
        _stream = stream;
        _hostKey = hostKey;
        _note = note;
    }

    public string ServerVersion { get; } = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13";
    public string ClientVersion { get; private set; } = "";

    /// <summary>Runs version exchange + key exchange. Returns false if the client bailed out.</summary>
    public async Task<bool> PerformHandshakeAsync(CancellationToken ct)
    {
        await ExchangeVersionsAsync(ct);
        _note($"SSH client version: {ClientVersion}");

        byte[] serverKexInit = BuildServerKexInit();
        await WritePacketAsync(serverKexInit, ct);

        byte[] clientKexInit = await ReadPacketAsync(ct);
        if (clientKexInit.Length == 0 || clientKexInit[0] != SshMessage.KexInit)
            return false;

        bool firstKexFollows = NegotiateAlgorithms(clientKexInit);

        byte[] packet = await ReadPacketAsync(ct);
        if (firstKexFollows && (packet.Length == 0 || packet[0] != SshMessage.KexDhInit))
        {
            // The client guessed a different algorithm; discard the guessed packet.
            packet = await ReadPacketAsync(ct);
        }
        if (packet.Length == 0 || packet[0] != SshMessage.KexDhInit)
            return false;

        await CompleteKeyExchangeAsync(clientKexInit, serverKexInit, packet, ct);

        // Server -> client traffic is encrypted once we have sent NEWKEYS.
        await WritePacketAsync(new[] { SshMessage.NewKeys }, ct);
        _writeEncrypted = true;

        byte[] clientNewKeys = await ReadPacketAsync(ct);
        if (clientNewKeys.Length == 0 || clientNewKeys[0] != SshMessage.NewKeys)
            return false;
        _readEncrypted = true;

        _note("SSH key exchange complete; transport encrypted.");
        return true;
    }

    private async Task ExchangeVersionsAsync(CancellationToken ct)
    {
        await _stream.WriteAsync(Encoding.ASCII.GetBytes(ServerVersion + "\r\n"), ct);
        await _stream.FlushAsync(ct);

        // Read lines until the SSH identification line; ignore any preamble.
        for (int i = 0; i < 5; i++)
        {
            string line = await ReadAsciiLineAsync(ct);
            if (line.StartsWith("SSH-", StringComparison.Ordinal))
            {
                ClientVersion = line;
                return;
            }
        }
        throw new InvalidOperationException("No SSH identification string received");
    }

    private byte[] BuildServerKexInit()
    {
        Span<byte> cookie = stackalloc byte[16];
        RandomNumberGenerator.Fill(cookie);

        return new SshWriter()
            .Byte(SshMessage.KexInit)
            .Raw(cookie)
            .NameList(OfferedKex)
            .NameList(OfferedHostKey)
            .NameList(OfferedCipher)   // enc c2s
            .NameList(OfferedCipher)   // enc s2c
            .NameList(OfferedMac)      // mac c2s
            .NameList(OfferedMac)      // mac s2c
            .NameList(OfferedComp)     // comp c2s
            .NameList(OfferedComp)     // comp s2c
            .NameList("")              // lang c2s
            .NameList("")              // lang s2c
            .Boolean(false)            // first_kex_packet_follows
            .UInt32(0)                 // reserved
            .ToArray();
    }

    private bool NegotiateAlgorithms(byte[] clientKexInit)
    {
        var reader = new SshReader(clientKexInit);
        reader.Byte();          // message type
        reader.Skip(16);        // cookie
        string[] kex = ParseNameList(reader.Utf8String());
        string[] hostKeys = ParseNameList(reader.Utf8String());
        string[] encC2S = ParseNameList(reader.Utf8String());
        string[] encS2C = ParseNameList(reader.Utf8String());
        reader.Utf8String();    // mac c2s
        reader.Utf8String();    // mac s2c
        reader.Utf8String();    // comp c2s
        reader.Utf8String();    // comp s2c
        reader.Utf8String();    // lang c2s
        reader.Utf8String();    // lang s2c
        bool firstKexFollows = reader.Boolean();

        _hostKeyAlgorithm = Choose(hostKeys, OfferedHostKey) ?? "rsa-sha2-512";
        _cipherC2S = Choose(encC2S, OfferedCipher) ?? "aes256-ctr";
        _cipherS2C = Choose(encS2C, OfferedCipher) ?? "aes256-ctr";
        string? chosenKex = Choose(kex, OfferedKex);
        _note($"SSH negotiated: kex={chosenKex}, hostkey={_hostKeyAlgorithm}, " +
              $"cipher c2s={_cipherC2S}, cipher s2c={_cipherS2C}");

        return firstKexFollows;
    }

    private async Task CompleteKeyExchangeAsync(
        byte[] clientKexInit, byte[] serverKexInit, byte[] kexDhInit, CancellationToken ct)
    {
        var reader = new SshReader(kexDhInit);
        reader.Byte(); // KexDhInit
        BigInteger e = reader.MpInt();

        var dh = new DiffieHellmanGroup14();
        BigInteger f = dh.PublicKey;
        BigInteger k = dh.ComputeSharedSecret(e);

        byte[] kBytes = new SshWriter().MpInt(k).ToArray();

        // Exchange hash H = SHA256(V_C || V_S || I_C || I_S || K_S || e || f || K).
        byte[] hashInput = new SshWriter()
            .String(ClientVersion)
            .String(ServerVersion)
            .String(clientKexInit)
            .String(serverKexInit)
            .String(_hostKey.PublicKeyBlob)
            .MpInt(e)
            .MpInt(f)
            .Raw(kBytes)
            .ToArray();
        byte[] h = SHA256.HashData(hashInput);

        byte[] signature = _hostKey.Sign(h, _hostKeyAlgorithm);

        byte[] reply = new SshWriter()
            .Byte(SshMessage.KexDhReply)
            .String(_hostKey.PublicKeyBlob)
            .MpInt(f)
            .String(signature)
            .ToArray();
        await WritePacketAsync(reply, ct);

        DeriveKeys(kBytes, h);
    }

    private void DeriveKeys(byte[] kBytes, byte[] h)
    {
        // session_id == H for the initial key exchange.
        byte[] ivC2S = Derive(kBytes, h, 'A', h, 16);
        byte[] ivS2C = Derive(kBytes, h, 'B', h, 16);
        byte[] keyC2S = Derive(kBytes, h, 'C', h, KeyLength(_cipherC2S));
        byte[] keyS2C = Derive(kBytes, h, 'D', h, KeyLength(_cipherS2C));
        _readMacKey = Derive(kBytes, h, 'E', h, 32);
        _writeMacKey = Derive(kBytes, h, 'F', h, 32);

        // We read client->server and write server->client.
        _readCipher = new CtrCipher(keyC2S, ivC2S);
        _writeCipher = new CtrCipher(keyS2C, ivS2C);
        _readCipherBlock = 16;
    }

    private static int KeyLength(string cipher) => cipher switch
    {
        "aes128-ctr" => 16,
        "aes256-ctr" => 32,
        _ => 32,
    };

    private static byte[] Derive(byte[] k, byte[] h, char letter, byte[] sessionId, int needed)
    {
        using var sha = SHA256.Create();
        var result = new List<byte>();

        byte[] first = sha.ComputeHash(Concat(k, h, new[] { (byte)letter }, sessionId));
        result.AddRange(first);

        while (result.Count < needed)
        {
            byte[] next = sha.ComputeHash(Concat(k, h, result.ToArray()));
            result.AddRange(next);
        }
        return result.Take(needed).ToArray();
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var all = new List<byte>();
        foreach (byte[] p in parts) all.AddRange(p);
        return all.ToArray();
    }

    // ---- Packet framing -------------------------------------------------------------------

    public async Task<byte[]> ReadPacketAsync(CancellationToken ct)
    {
        if (!_readEncrypted)
            return await ReadPlainPacketAsync(ct);
        return await ReadEncryptedPacketAsync(ct);
    }

    private async Task<byte[]> ReadPlainPacketAsync(CancellationToken ct)
    {
        byte[] header = await ReadFullyAsync(5, ct);
        uint packetLength = (uint)((header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3]);
        byte paddingLength = header[4];
        if (packetLength is < 1 or > 35000)
            throw new InvalidOperationException("Bad SSH packet length");

        int payloadLength = (int)packetLength - paddingLength - 1;
        byte[] body = await ReadFullyAsync((int)packetLength - 1, ct);
        _readSeq++;
        return body[..payloadLength];
    }

    private async Task<byte[]> ReadEncryptedPacketAsync(CancellationToken ct)
    {
        byte[] firstBlock = await ReadFullyAsync(_readCipherBlock, ct);
        _readCipher!.Process(firstBlock);

        uint packetLength = (uint)((firstBlock[0] << 24) | (firstBlock[1] << 16) | (firstBlock[2] << 8) | firstBlock[3]);
        if (packetLength is < 1 or > 35000)
            throw new InvalidOperationException("Bad encrypted SSH packet length");

        int total = (int)packetLength + 4;
        byte[] plaintext = new byte[total];
        firstBlock.CopyTo(plaintext, 0);

        if (total > _readCipherBlock)
        {
            byte[] rest = await ReadFullyAsync(total - _readCipherBlock, ct);
            _readCipher.Process(rest);
            rest.CopyTo(plaintext, _readCipherBlock);
        }

        byte[] mac = await ReadFullyAsync(32, ct); // hmac-sha2-256
        VerifyMac(plaintext, mac);

        byte paddingLength = plaintext[4];
        int payloadLength = (int)packetLength - paddingLength - 1;
        _readSeq++;
        return plaintext.AsSpan(5, payloadLength).ToArray();
    }

    private void VerifyMac(byte[] plaintext, byte[] mac)
    {
        Span<byte> seqAndData = new byte[4 + plaintext.Length];
        seqAndData[0] = (byte)(_readSeq >> 24);
        seqAndData[1] = (byte)(_readSeq >> 16);
        seqAndData[2] = (byte)(_readSeq >> 8);
        seqAndData[3] = (byte)_readSeq;
        plaintext.CopyTo(seqAndData[4..]);

        byte[] expected = HMACSHA256.HashData(_readMacKey, seqAndData);
        if (!CryptographicOperations.FixedTimeEquals(expected, mac))
            throw new InvalidOperationException("SSH MAC verification failed");
    }

    public async Task WritePacketAsync(byte[] payload, CancellationToken ct)
    {
        int blockSize = _writeEncrypted ? 16 : 8;
        int paddingLength = blockSize - ((5 + payload.Length) % blockSize);
        if (paddingLength < 4)
            paddingLength += blockSize;

        uint packetLength = (uint)(1 + payload.Length + paddingLength);
        byte[] padding = new byte[paddingLength];
        RandomNumberGenerator.Fill(padding);

        byte[] plaintext = new byte[4 + packetLength];
        plaintext[0] = (byte)(packetLength >> 24);
        plaintext[1] = (byte)(packetLength >> 16);
        plaintext[2] = (byte)(packetLength >> 8);
        plaintext[3] = (byte)packetLength;
        plaintext[4] = (byte)paddingLength;
        payload.CopyTo(plaintext, 5);
        padding.CopyTo(plaintext, 5 + payload.Length);

        if (_writeEncrypted)
        {
            Span<byte> seqAndData = new byte[4 + plaintext.Length];
            seqAndData[0] = (byte)(_writeSeq >> 24);
            seqAndData[1] = (byte)(_writeSeq >> 16);
            seqAndData[2] = (byte)(_writeSeq >> 8);
            seqAndData[3] = (byte)_writeSeq;
            plaintext.CopyTo(seqAndData[4..]);
            byte[] mac = HMACSHA256.HashData(_writeMacKey, seqAndData);

            byte[] ciphertext = (byte[])plaintext.Clone();
            _writeCipher!.Process(ciphertext);

            await _stream.WriteAsync(ciphertext, ct);
            await _stream.WriteAsync(mac, ct);
        }
        else
        {
            await _stream.WriteAsync(plaintext, ct);
        }
        await _stream.FlushAsync(ct);
        _writeSeq++;
    }

    // ---- Low-level IO ---------------------------------------------------------------------

    private async Task<byte[]> ReadFullyAsync(int count, CancellationToken ct)
    {
        byte[] buffer = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = await _stream.ReadAsync(buffer.AsMemory(read, count - read), ct);
            if (n == 0)
                throw new EndOfStreamException("SSH peer closed the connection");
            read += n;
        }
        return buffer;
    }

    private async Task<string> ReadAsciiLineAsync(CancellationToken ct)
    {
        var sb = new StringBuilder();
        var one = new byte[1];
        while (sb.Length < 512)
        {
            if (await _stream.ReadAsync(one, ct) == 0)
                break;
            if (one[0] == (byte)'\n')
                break;
            if (one[0] != (byte)'\r')
                sb.Append((char)one[0]);
        }
        return sb.ToString();
    }

    private static string[] ParseNameList(string list) =>
        list.Split(',', StringSplitOptions.RemoveEmptyEntries);

    private static string? Choose(string[] clientList, string[] serverList) =>
        clientList.FirstOrDefault(serverList.Contains);

    public void Dispose()
    {
        _readCipher?.Dispose();
        _writeCipher?.Dispose();
    }
}

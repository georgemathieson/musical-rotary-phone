using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace NetworkMonitor.Server.Ssh;

/// <summary>
/// The 2048-bit MODP group 14 (RFC 3526) used by diffie-hellman-group14-sha256.
/// Enough to complete the key exchange so a real SSH client proceeds to authentication.
/// </summary>
internal sealed class DiffieHellmanGroup14
{
    private const string PrimeHex =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

    public static readonly BigInteger P = BigInteger.Parse("0" + PrimeHex, NumberStyles.HexNumber);
    public static readonly BigInteger G = 2;

    public BigInteger PrivateKey { get; }
    public BigInteger PublicKey { get; }

    public DiffieHellmanGroup14()
    {
        // Ephemeral private exponent: a random value comfortably within (1, P-1).
        Span<byte> raw = stackalloc byte[256];
        RandomNumberGenerator.Fill(raw);
        var r = new BigInteger(raw, isUnsigned: true, isBigEndian: true);
        PrivateKey = (r % (P - 3)) + 2;
        PublicKey = BigInteger.ModPow(G, PrivateKey, P);
    }

    /// <summary>Validates the peer's public value and derives the shared secret K.</summary>
    public BigInteger ComputeSharedSecret(BigInteger peerPublic)
    {
        if (peerPublic <= BigInteger.One || peerPublic >= P - 1)
            throw new ArgumentOutOfRangeException(nameof(peerPublic), "Peer DH value out of range");
        return BigInteger.ModPow(peerPublic, PrivateKey, P);
    }
}

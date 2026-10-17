using System.Numerics;
using System.Security.Cryptography;
using NetworkMonitor.Server.Ssh;

namespace NetworkMonitor.Server.Services;

/// <summary>
/// Holds the RSA host key the fake SSH server presents. Generated once at startup; it only
/// ever signs the key-exchange hash, so a real client will complete the handshake and
/// proceed to send its login attempt.
/// </summary>
public sealed class SshHostKeyProvider
{
    private readonly RSA _rsa;

    public SshHostKeyProvider()
    {
        _rsa = RSA.Create(2048);
        RSAParameters p = _rsa.ExportParameters(includePrivateParameters: false);
        var e = new BigInteger(p.Exponent!, isUnsigned: true, isBigEndian: true);
        var n = new BigInteger(p.Modulus!, isUnsigned: true, isBigEndian: true);

        PublicKeyBlob = new SshWriter()
            .String("ssh-rsa")
            .MpInt(e)
            .MpInt(n)
            .ToArray();
    }

    /// <summary>The host key in SSH "ssh-rsa" wire format (K_S).</summary>
    public byte[] PublicKeyBlob { get; }

    /// <summary>Signs the exchange hash and returns the SSH signature blob for the algorithm.</summary>
    public byte[] Sign(byte[] data, string algorithm)
    {
        HashAlgorithmName hash = algorithm switch
        {
            "rsa-sha2-512" => HashAlgorithmName.SHA512,
            "rsa-sha2-256" => HashAlgorithmName.SHA256,
            _ => HashAlgorithmName.SHA1, // "ssh-rsa"
        };

        byte[] signature = _rsa.SignData(data, hash, RSASignaturePadding.Pkcs1);
        return new SshWriter()
            .String(algorithm)
            .String(signature)
            .ToArray();
    }
}

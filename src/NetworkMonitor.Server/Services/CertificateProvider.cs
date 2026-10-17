using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NetworkMonitor.Server.Services;

/// <summary>
/// Supplies a single self-signed certificate used to terminate TLS on the fake HTTPS port.
/// Most scanners ignore certificate validation, so this lets us read their decrypted requests.
/// </summary>
public sealed class CertificateProvider
{
    public CertificateProvider()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, false, 0, true));

        using X509Certificate2 ephemeral = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        // Round-trip through PFX so the private key is usable by SslStream on all platforms.
        Certificate = X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null);
    }

    public X509Certificate2 Certificate { get; }
}

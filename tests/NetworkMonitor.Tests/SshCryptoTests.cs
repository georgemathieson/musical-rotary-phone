using System.Numerics;
using System.Text;
using NetworkMonitor.Server.Ssh;

namespace NetworkMonitor.Tests;

public class SshWireTests
{
    [Fact]
    public void WriterReader_RoundTripsPrimitiveTypes()
    {
        byte[] encoded = new SshWriter()
            .Byte(42)
            .Boolean(true)
            .UInt32(0xDEADBEEF)
            .String("hello")
            .MpInt(new BigInteger(0x1234567890))
            .NameList("aes256-ctr", "aes128-ctr")
            .ToArray();

        var reader = new SshReader(encoded);
        Assert.Equal(42, reader.Byte());
        Assert.True(reader.Boolean());
        Assert.Equal(0xDEADBEEF, reader.UInt32());
        Assert.Equal("hello", reader.Utf8String());
        Assert.Equal(new BigInteger(0x1234567890), reader.MpInt());
        Assert.Equal("aes256-ctr,aes128-ctr", reader.Utf8String());
    }

    [Fact]
    public void MpInt_PrependsZeroWhenHighBitSet()
    {
        // 0x80 has the high bit set, so the mpint body must be 00 80 (5 bytes incl. length).
        byte[] encoded = new SshWriter().MpInt(new BigInteger(0x80)).ToArray();
        Assert.Equal(new byte[] { 0, 0, 0, 2, 0x00, 0x80 }, encoded);
    }

    [Fact]
    public void MpInt_Zero_EncodesAsEmptyString()
    {
        byte[] encoded = new SshWriter().MpInt(BigInteger.Zero).ToArray();
        Assert.Equal(new byte[] { 0, 0, 0, 0 }, encoded);
    }
}

public class DiffieHellmanTests
{
    [Fact]
    public void BothParties_DeriveTheSameSharedSecret()
    {
        var alice = new DiffieHellmanGroup14();
        var bob = new DiffieHellmanGroup14();

        BigInteger aliceSecret = alice.ComputeSharedSecret(bob.PublicKey);
        BigInteger bobSecret = bob.ComputeSharedSecret(alice.PublicKey);

        Assert.Equal(aliceSecret, bobSecret);
        Assert.True(aliceSecret > BigInteger.One);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void ComputeSharedSecret_RejectsDegeneratePeerValues(int peer)
    {
        var dh = new DiffieHellmanGroup14();
        Assert.Throws<ArgumentOutOfRangeException>(() => dh.ComputeSharedSecret(peer));
    }
}

public class CtrCipherTests
{
    // NIST SP 800-38A, F.5.1 CTR-AES128.Encrypt (first block).
    [Fact]
    public void Ctr_MatchesNistAes128TestVector()
    {
        byte[] key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] plaintext = Convert.FromHexString("6bc1bee22e409f96e93d7e117393172a");
        byte[] expected = Convert.FromHexString("874d6191b620e3261bef6864990db6ce");

        using var cipher = new CtrCipher(key, iv);
        byte[] buffer = (byte[])plaintext.Clone();
        cipher.Process(buffer);

        Assert.Equal(expected, buffer);
    }

    [Fact]
    public void Ctr_EncryptThenDecrypt_RoundTrips()
    {
        byte[] key = Convert.FromHexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        byte[] iv = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] message = Encoding.ASCII.GetBytes("sixteen bytes!!!thirty-two bytes exactly here!!!");

        using var enc = new CtrCipher(key, iv);
        using var dec = new CtrCipher(key, iv);

        byte[] buffer = (byte[])message.Clone();
        enc.Process(buffer);
        Assert.NotEqual(message, buffer);   // actually encrypted
        dec.Process(buffer);
        Assert.Equal(message, buffer);      // and reversible
    }
}

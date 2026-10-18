using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;

namespace NetworkMonitor.Server.Auth;

/// <summary>
/// The single dashboard login. The password is only ever stored as a salted PBKDF2 hash
/// (ASP.NET Core Identity's <see cref="PasswordHasher{TUser}"/>); create one with the
/// <c>hash-password</c> command.
/// </summary>
public sealed class DashboardCredentials
{
    private const string HashSubject = "dashboard";
    private const string GeneratedAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    private static readonly PasswordHasher<string> Hasher = new();

    private readonly byte[] _usernameDigest;
    private readonly string _passwordHash;

    public DashboardCredentials(string username, string passwordHash)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("A dashboard username is required.", nameof(username));
        if (!LooksLikeHash(passwordHash))
            throw new InvalidOperationException(
                "Dashboard:PasswordHash is not a valid password hash. Generate one with 'hash-password'.");

        Username = username;
        _usernameDigest = Digest(username);
        _passwordHash = passwordHash;
    }

    public string Username { get; }

    public static string HashPassword(string password) => Hasher.HashPassword(HashSubject, password);

    public bool Verify(string? username, string? password)
    {
        // Compare fixed-length digests so timing reveals neither the username nor its length, and
        // always run the slow password check so a wrong username costs as much as a wrong password.
        bool userMatches = CryptographicOperations.FixedTimeEquals(Digest(username ?? ""), _usernameDigest);
        bool passwordMatches = Hasher.VerifyHashedPassword(HashSubject, _passwordHash, password ?? "")
            != PasswordVerificationResult.Failed;
        return userMatches && passwordMatches;
    }

    /// <summary>
    /// Reads <c>Dashboard:Username</c> and <c>Dashboard:PasswordHash</c>. With no hash configured it
    /// generates a random password for this run and logs it once, so the dashboard is never open.
    /// </summary>
    public static DashboardCredentials FromConfiguration(IConfiguration config, ILogger logger)
    {
        string username = config["Dashboard:Username"] is { Length: > 0 } configured ? configured : "admin";
        string? hash = config["Dashboard:PasswordHash"];
        if (!string.IsNullOrWhiteSpace(hash))
            return new DashboardCredentials(username, hash);

        string generated = RandomNumberGenerator.GetString(GeneratedAlphabet, 24);
        logger.LogWarning(
            "No Dashboard:PasswordHash is configured, so a one-time login was generated for this run: " +
            "username '{Username}', password '{Password}'. Set Dashboard:PasswordHash (see 'hash-password') " +
            "to make it permanent.",
            username, generated);
        return new DashboardCredentials(username, HashPassword(generated));
    }

    private static byte[] Digest(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));

    /// <summary>Identity v2 (0x00) or v3 (0x01) hash format, base64 encoded.</summary>
    private static bool LooksLikeHash(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        try
        {
            byte[] bytes = Convert.FromBase64String(value);
            return bytes.Length > 16 && bytes[0] is 0x00 or 0x01;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

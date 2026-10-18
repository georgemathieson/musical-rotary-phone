using System.Text;

namespace NetworkMonitor.Server.Auth;

/// <summary>
/// <c>NetworkMonitor.Server hash-password</c>: prompts for a password (or reads one line from
/// stdin) and prints the hash to put in <c>Dashboard:PasswordHash</c>. The password is never taken
/// as a command-line argument, so it does not end up in shell history.
/// </summary>
internal static class PasswordTool
{
    private const int MinimumLength = 12;

    public static int Run()
    {
        Console.Error.Write("Password: ");
        string password = ReadSecret();

        if (!Console.IsInputRedirected)
        {
            Console.Error.Write("Confirm password: ");
            if (ReadSecret() != password)
            {
                Console.Error.WriteLine("Passwords do not match.");
                return 1;
            }
        }

        if (password.Length < MinimumLength)
        {
            Console.Error.WriteLine($"Use at least {MinimumLength} characters.");
            return 1;
        }

        Console.WriteLine(DashboardCredentials.HashPassword(password));
        return 0;
    }

    private static string ReadSecret()
    {
        if (Console.IsInputRedirected)
            return Console.ReadLine() ?? "";

        var sb = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                return sb.ToString();
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                    sb.Length--;
                continue;
            }
            if (!char.IsControl(key.KeyChar))
                sb.Append(key.KeyChar);
        }
    }
}

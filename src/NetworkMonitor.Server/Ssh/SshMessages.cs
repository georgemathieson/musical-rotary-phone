namespace NetworkMonitor.Server.Ssh;

/// <summary>SSH transport and user-auth message numbers (RFC 4253 / RFC 4252).</summary>
internal static class SshMessage
{
    public const byte Disconnect = 1;
    public const byte Ignore = 2;
    public const byte Unimplemented = 3;
    public const byte Debug = 4;
    public const byte ServiceRequest = 5;
    public const byte ServiceAccept = 6;
    public const byte KexInit = 20;
    public const byte NewKeys = 21;
    public const byte KexDhInit = 30;
    public const byte KexDhReply = 31;
    public const byte UserAuthRequest = 50;
    public const byte UserAuthFailure = 51;
    public const byte UserAuthSuccess = 52;
    public const byte UserAuthBanner = 53;
    public const byte UserAuthInfoRequest = 60;
    public const byte UserAuthInfoResponse = 61;
}

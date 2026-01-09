using System.Security.Cryptography;

namespace AuthServer.Main.Common;

public static class CommonUtility
{
    public static byte[] HashPassword(byte[] password)
    {
        // Stub implementation: SHA256 hash
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(password);
        }
    }
}

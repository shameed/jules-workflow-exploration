using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Main.Common;

public static class SimpleCrypter
{
    public static string DecryptString(string cipherText)
    {
        // Stub implementation: return as is (for now, to allow compilation)
        // In real migration, replace with compatible decryption logic
        return cipherText;
    }

    public static string EncryptString(string plainText)
    {
        // Stub implementation: return as is
        return plainText;
    }
}

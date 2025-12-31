using System.Threading.Tasks;

namespace Baic.AuthMain.Resources
{
    public interface IOtpService
    {
        Task<string> GenerateAndStoreOtp(string userId);
        Task<bool> VerifyOtp(string userId, string otp);
    }
}
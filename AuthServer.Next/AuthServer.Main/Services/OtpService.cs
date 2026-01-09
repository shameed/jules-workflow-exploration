using Microsoft.AspNetCore.Identity;
using AuthServer.Main.Models;
using System;
using System.Threading.Tasks;

namespace AuthServer.Main.Services
{

    public class OtpService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private static readonly Random random = new Random();

        public OtpService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<string> GenerateAndStoreOtp(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var otp = GenerateOtp();

            user.Otp = otp;
            user.OtpExpiration = DateTime.Now.AddMinutes(5); // Set the OTP expiration time as needed

            await _userManager.UpdateAsync(user);

            return otp;
        }

        public async Task<bool> VerifyOtp(string userId, string otp)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null || user.Otp != otp || user.OtpExpiration < DateTime.Now)
            {
                return false;
            }

            // OTP is valid, clear the OTP and expiration time
            user.Otp = null;
            user.OtpExpiration = null;

            await _userManager.UpdateAsync(user);

            return true;
        }
        private string GenerateOtp()
        {
            int otpLength = 6; // Change the OTP length as needed
            const string characters = "1234567890";
            char[] otp = new char[otpLength];

            for (int i = 0; i < otpLength; i++)
            {
                otp[i] = characters[random.Next(characters.Length)];
            }

            return new string(otp);
        }
    }

}

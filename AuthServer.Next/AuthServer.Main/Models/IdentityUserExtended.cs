using Microsoft.AspNetCore.Identity;
using System;

namespace AuthServer.Main.Models
{
    public class IdentityUserExtended: IdentityUser
    {

        public long UserPk { get; set; }
        public string UserId { get; set; }
        public string UserType { get; set; }
        public string Language { get; set; }
        public string Otp { get; set; }
        public DateTime? OtpExpiration { get; set; }

    }
}

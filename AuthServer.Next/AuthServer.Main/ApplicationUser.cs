using Microsoft.AspNetCore.Identity;

namespace AuthServer.Main;

public class ApplicationUser : IdentityUser
{
    public bool MustChangePassword { get; set; }
    public string? ProfileData { get; set; }
}

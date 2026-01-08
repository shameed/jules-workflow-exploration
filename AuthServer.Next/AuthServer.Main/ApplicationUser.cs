using Microsoft.AspNetCore.Identity;

namespace AuthServer.Main;

public class ApplicationUser : IdentityUser
{
    public bool MustChangePassword { get; set; }
    public string? ProfileData { get; set; }

    public long UserPk { get; set; }
    public string? UserId { get; set; }
    public string? UserType { get; set; }
    public string? Language { get; set; }
    public long EditVersion { get; set; }
    public string? IsMfaEnabledCompany { get; set; }
    public bool IsMfaEnabledUser { get; set; }
    public string? MfaType { get; set; }
    public string? MfaStatus { get; set; }
    public long DiaryDisplayDays { get; set; }
    public bool IsBankIcon { get; set; }
    public bool IsHelpDesk { get; set; }
    public long UserClientPk { get; set; }
    public string? FirstName { get; set; }
    public string? MiddleName { get; set; }
    public string? LastName { get; set; }
    public string? AuthType { get; set; }
    public string? Type { get; set; }
    public bool IsUnderwriter { get; set; }
    public int Status { get; set; }
    public string? Department { get; set; }
    public string? AnchorPage { get; set; }
    public bool IsInspection { get; set; }

    public long Logged { get; set; }
    public string? Message { get; set; }
}

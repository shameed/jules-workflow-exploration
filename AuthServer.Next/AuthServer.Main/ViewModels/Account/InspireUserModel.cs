using System;

namespace AuthServer.Main.ViewModels.Account;

public class InspireUserModel
{
    public long ASUserPk { get; set; }
    public string ASUserId { get; set; }
    public string FirstName { get; set; }
    public string MiddleName { get; set; }
    public string LastName { get; set; }
    public string AuthType { get; set; }
    public string Type { get; set; }
    public string Email { get; set; }
    public long Logged { get; set; }
    public long PremiumLimit { get; set; }
    public long PayLimit { get; set; }
    public long IssueCoId { get; set; }
    public string ASStatus { get; set; }
    public string Department { get; set; }
    public string JobTitle { get; set; }
    public string LicenseNo { get; set; }
    public string SupervisorId { get; set; }
    public DateTime EffectiveFrom { get; set; }
    public DateTime EffectiveTo { get; set; }
    public string AnchorPage { get; set; }
    public string Language { get; set; }
    public long DiaryDisplayDays { get; set; }
    public bool IsUnderwriter { get; set; }
    public bool IsBankIcon { get; set; }
    public bool IsHelpDesk { get; set; }
    public long UserClientPk { get; set; }
    public string IsMfaEnabledCompany { get; set; }
    public bool IsMfaEnabledUser { get; set; }
    public string MfaType { get; set; }
    public string MfaStatus { get; set; }
    public bool IsInspection { get; set; }

}
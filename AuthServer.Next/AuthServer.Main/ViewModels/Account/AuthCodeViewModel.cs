using System.ComponentModel.DataAnnotations;

namespace AuthServer.Main.ViewModels.Account;
public class AuthCodeViewModel
{
    [Required]
    [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
    [DataType(DataType.Text)]
    [Display(Name = "Verification Code")]
    public string Code { get; set; }
    public string UserName { get; set; }
    public string ReturnUrl { get; set; }
    public string MfaStatus { get; set; }
}
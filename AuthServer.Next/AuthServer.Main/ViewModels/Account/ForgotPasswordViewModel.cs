using System.ComponentModel.DataAnnotations;

namespace AuthServer.Main.ViewModels.Account;

public class ForgotPasswordViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}

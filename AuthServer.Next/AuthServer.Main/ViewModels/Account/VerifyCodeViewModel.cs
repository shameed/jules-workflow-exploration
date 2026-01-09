using System.ComponentModel.DataAnnotations;

namespace AuthServer.Main.ViewModels.Account;

public class VerifyCodeViewModel
{

    [Required(ErrorMessage = "CODE_REQUIRED")]
    public string AuthenticatorCode { get; set; }
    public string ReturnUrl { get; set; }
    public bool RememberBrowser { get; set; }
    public bool RememberMe { get; set; }
}

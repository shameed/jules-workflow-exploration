using System.ComponentModel.DataAnnotations;

namespace AuthServer.Main.ViewModels.Account;

public class LoginInputModel
{
    [Required(ErrorMessage = "User ID is Required")]
    public string Username { get; set; }
    [Required(ErrorMessage = "Password is Required")]
    public string Password { get; set; }
    public bool RememberLogin { get; set; }
    public string ReturnUrl { get; set; }
}
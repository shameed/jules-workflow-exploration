using System.ComponentModel.DataAnnotations;

namespace Baic.AuthMain.Models.AccountViewModels;
public class TwoFactorLoginViewModel
{
    [Required]
    [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
    [DataType(DataType.Text)]
    [Display(Name = "Authenticator code")]
    public string TwoFactorCode { get; set; }
}

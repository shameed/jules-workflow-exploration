using System.ComponentModel.DataAnnotations;

namespace Baic.AuthMain.Models.ManageViewModels;

public class ChangePasswordViewModel
{
    [Required(ErrorMessage = "CURRENT_PASSWORD_REQUIRED")]
    [DataType(DataType.Password)]
    public string OldPassword { get; set; }

    [Required(ErrorMessage = "NEW_PASSWORD_REQUIRED")]    
    [StringLength(50, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 8)]
    [RegularExpression(@"^((?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*#?&])).+$", ErrorMessage = "The {0} must contain atleast one uppercase and special character.")]
    [DataType(DataType.Password)]
    public string NewPassword { get; set; }

    [DataType(DataType.Password)]
    [Compare("NewPassword", ErrorMessage = "CONFIRM_PASSWORD_NOT_MATCHING")]
    public string ConfirmPassword { get; set; }

    public string StatusMessage { get; set; }
}

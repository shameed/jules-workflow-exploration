
using System.ComponentModel.DataAnnotations;

namespace Baic.AuthMain.Models.AccountViewModels;
public class ChangePasswordViewModel
{
    public long userPK { get; set; }
    [Required]
    public string UserId { get; set; }
    public string ReturnUrl { get; set; }

    [Required(ErrorMessage = "Current Password should not be blank")]

    public string CurrentPassword { get; set; }


    [Required(ErrorMessage = "New Password should not be blank")]
    [StringLength(50, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 8)]
    [RegularExpression(@"^((?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*#?&])).+$", ErrorMessage = "The {0} must contain atleast one uppercase and special character.")]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string NewPassword { get; set; }

    [Required(ErrorMessage = "Confirm Password should not be blank")]
    [Compare("NewPassword", ErrorMessage = "New Password and Confirm Password does not match.")]
    public string ConfirmPassword { get; set; }
}
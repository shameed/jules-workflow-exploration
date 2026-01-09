using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace AuthServer.Main.ViewModels.Account;

public class ForgotPasswordViewModel
{
    [Required(ErrorMessage = "EMAIL_REQUIRED")]
    [EmailAddress(ErrorMessage = "EMAIL_INVALID")]
    public string Email { get; set; }

    public class SiQuestion
    {
        public string QuestionText { get; set; }
        public string AnswerId { get; set; }
    }

    public class SiForgotPasswordModel
    {
        public string UserId { get; set; }
        public string EmailId { get; set; }
        public List<SiQuestion> Questions { get; set; }
    }
}

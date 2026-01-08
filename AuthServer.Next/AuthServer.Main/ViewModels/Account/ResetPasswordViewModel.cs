using System.Collections.Generic;
using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;

namespace AuthServer.Main.ViewModels.Account;

public class ResetPasswordViewModel:IValidatableObject
{
    public string UserId { get; set; }

    public string ReturnUrl { get; set; }

    [Required(ErrorMessage = "New Password should not be blank")]
    public string NewPassword { get; set; }

    [Required(ErrorMessage = "Confirm Password should not be blank")]
    [Compare("NewPassword", ErrorMessage = "New Password and Confirm Password does not match.")]
    public string ConfirmPassword { get; set; }
    public string Question1 { get; set; }
    public string Question2 { get; set; }
    public string Question3 { get; set; }
    public string Answer1 { get; set; }
    public string Answer2 { get; set; }
    public string Answer3 { get; set; }
    public string ErrorMessage { get; set; }
    public bool IsPasswordQuestions { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (IsPasswordQuestions == true)
        {
            if (string.IsNullOrEmpty(Question1) || Question1.Trim() == "")
            {
                yield return new ValidationResult("Question 1 should not be blank", new List<string> { "Question1" });
            }
            if (string.IsNullOrEmpty(Question2) || Question2.Trim() == "")
            {
                yield return new ValidationResult("Question 2 should not be blank", new List<string> { "Question2" });
            }
            if (string.IsNullOrEmpty(Question3) || Question3.Trim() == "")
            {
                yield return new ValidationResult("Question 3 should not be blank", new List<string> { "Question3" });
            }
            if (string.IsNullOrEmpty(Answer1) || Answer1.Trim() == "")
            {
                yield return new ValidationResult("Answer 1 should not be blank", new List<string> { "Answer1" });
            }
            if (string.IsNullOrEmpty(Answer2) || Answer2.Trim() == "")
            {
                yield return new ValidationResult("Answer 2 should not be blank", new List<string> { "Answer2" });
            }
            if (string.IsNullOrEmpty(Answer3) || Answer3.Trim() == "")
            {
                yield return new ValidationResult("Answer 3 should not be blank", new List<string> { "Answer3" });
            }
        }

        NewPassword = NewPassword.Trim();
        if (NewPassword.Equals(UserId.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            yield return new ValidationResult("Password should not be same as User ID", new List<string> { "NewPassword" });
        }
        if (NewPassword.Length < 8)
        {
            yield return new ValidationResult("Password must be at least 8 characters", new List<string> { "NewPassword" });
        }
        if (NewPassword.Length > 25)
        {
            yield return new ValidationResult("Password should not exceed 25 characters", new List<string> { "NewPassword" });
        }
        if (!NewPassword.Any(char.IsUpper))
        {
            yield return new ValidationResult("Password must have atleast one upper case alphabet", new List<string> { "NewPassword" });
        }
        if (!NewPassword.Any(char.IsNumber))
        {
            yield return new ValidationResult("Password must have atleast one numeric character", new List<string> { "NewPassword" });
        }
        if (!NewPassword.Any(char.IsLower))
        {
            yield return new ValidationResult("Password must have atleast one lower case alphabet", new List<string> { "NewPassword" });
        }
        if (!NewPassword.Any(ch => !char.IsLetterOrDigit(ch)))
        {
            yield return new ValidationResult("Password must have atleast one special character", new List<string> { "NewPassword" });
        }
        if (!Char.IsLetter(NewPassword[0]))
        {
            yield return new ValidationResult("Password must starts with an alphabet", new List<string> { "NewPassword" });
        }

        if (!string.IsNullOrEmpty(Question1) && !string.IsNullOrEmpty(Question2))
        {
            if (Question1.Trim().Equals(Question2.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationResult("Question1 should not be same as Question2", new List<string> { "Question1" });
            }
        }
        if (!string.IsNullOrEmpty(Question1) && !string.IsNullOrEmpty(Question3))
        {
            if (Question1.Trim().Equals(Question3.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationResult("Question1 should not be same as Question3", new List<string> { "Question1" });
            }
        }
        if (!string.IsNullOrEmpty(Question2) && !string.IsNullOrEmpty(Question3))
        {
            if (Question2.Trim().Equals(Question3.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationResult("Question2 should not be same as Question3", new List<string> { "Question2" });
            }
        }
        if (!string.IsNullOrEmpty(Answer1) && !string.IsNullOrEmpty(Answer2))
        {
            if (Answer1.Trim().Equals(Answer2.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationResult("Answer1 should not be same as Answer2", new List<string> { "Answer1" });
            }
        }
        if (!string.IsNullOrEmpty(Answer1) && !string.IsNullOrEmpty(Answer3))
        {
            if (Answer1.Trim().Equals(Answer3.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationResult("Answer1 should not be same as Answer3", new List<string> { "Answer1" });
            }
        }
        if (!string.IsNullOrEmpty(Answer2) && !string.IsNullOrEmpty(Answer3))
        {
            if (Answer2.Trim().Equals(Answer3.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationResult("Answer2 should not be same as Answer3", new List<string> { "Answer2" });
            }
        }
    }
}
public class SIQuestionsAnswers
{
    public string QuestionText { get; set; }
    public string QuestionId { get; set; }
    public string AnswerText { get; set; }
    public string AnswerId { get; set; }
}
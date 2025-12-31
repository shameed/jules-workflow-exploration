namespace Baic.AuthMain.Models.AccountViewModels
{
    public class QuestionsAnswer
    {
        public string QuestionText { get; set; }
        public string QuestionId { get; set; }
        public string AnswerText { get; set; }
        public string AnswerId { get; set; }
    }

    public class ResetPasswordModel
    {
        public string UserId { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmPassword { get; set; }
        public string ReturnUrl { get; set; }
        public string Question1 { get; set; }
        public string Question2 { get; set; }
        public string Question3 { get; set; }
        public string Answer1 { get; set; }
        public string Answer2 { get; set; }
        public string Answer3 { get; set; }
        public string ErrorMessage { get; set; }
        public bool? IsPasswordQuestions { get; set; }
    }
}

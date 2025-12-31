using System.Collections.Generic;

namespace Baic.AuthMain.Models
{
    public class Question
    {
        public string QuestionText { get; set; }
        public string AnswerId { get; set; }
    }

    public class ForgetPasswordModel
    {
        public string UserId { get; set; }
        public string EmailId { get; set; }
        public List<Question> Questions { get; set; }
    }
}

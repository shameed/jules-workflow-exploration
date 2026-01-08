namespace AuthServer.Main.ViewModels.Account
{
    public class ResetPasswordDM
    {
        public string UserID { get; set; }
        public string NewPassword { get; set; }
        public string Question1 { get; set; }
        public string Answer1 { get; set; }
        public string Question2 { get; set; }
        public string Answer2 { get; set; }
        public string Question3 { get; set; }
        public string Answer3 { get; set; }
    }
}

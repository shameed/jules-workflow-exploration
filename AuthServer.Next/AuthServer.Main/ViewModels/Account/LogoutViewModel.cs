namespace AuthServer.Main.ViewModels.Account;

public class LogoutViewModel : LogoutInputModel
{
    public bool ShowLogoutPrompt { get; set; } = true;
}

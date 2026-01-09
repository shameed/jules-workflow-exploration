namespace AuthServer.Main.Models;

public class MfaModel
{
    public bool RememberMe { get; set; }

    public string ReturnUrl { get; set; }
}
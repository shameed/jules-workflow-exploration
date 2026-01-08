using System.ComponentModel.DataAnnotations;

namespace AuthServer.Main.ViewModels.Authorization;

public class AuthorizeViewModel
{
    [Display(Name = "Application")]
    public string? ApplicationName { get; set; }

    [Display(Name = "Scope")]
    public string? Scopes { get; set; }
}

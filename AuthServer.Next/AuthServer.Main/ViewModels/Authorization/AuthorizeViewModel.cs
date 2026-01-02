using System.ComponentModel.DataAnnotations;

namespace AuthServer.Main.ViewModels.Authorization;

public class AuthorizeViewModel
{
    [Display(Name = "Application")]
    public string? ApplicationName { get; set; }

    [Display(Name = "Scope")]
    public string? Scope { get; set; }

    public IEnumerable<string> Scopes { get; set; } = new List<string>();
}

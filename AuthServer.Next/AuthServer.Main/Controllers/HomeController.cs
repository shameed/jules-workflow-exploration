using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using AuthServer.Main.Models;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore;

namespace AuthServer.Main.Controllers;

public class HomeController : Controller
{
    public HomeController()
    {
    }

    public IActionResult Index()
    {
        return View();
    }

    /// <summary>
    /// Shows the error page
    /// </summary>
    public IActionResult Error(string errorId)
    {
        var vm = new ErrorViewModel();
        // Simple error handling for now. OpenIddict usually handles errors via standard responses.
        // If we need specific error details, we'd inspect the request or use OpenIddict events.
        vm.Error = new IdentityServer4.Models.ErrorMessage { Error = errorId }; // Temporary mapping or simply use string

        return View("Error", vm);
    }
}

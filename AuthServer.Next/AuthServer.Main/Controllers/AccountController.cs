using System.Text.Encodings.Web;
using AuthServer.Main.Services;
using AuthServer.Main.ViewModels.Account;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using AutoMapper;
using Microsoft.Extensions.Localization;
using AuthServer.Main.Models;

namespace AuthServer.Main.Controllers;

[Authorize]
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<AccountController> _logger;
    private readonly IInspireUser _inspireUser;
    private readonly OtpService _otpService;
    private readonly IMapper _mapper;
    private readonly IConfiguration _configuration;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IEmailSender emailSender,
        ILogger<AccountController> logger,
        IInspireUser inspireUser,
        OtpService otpService,
        IMapper mapper,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _emailSender = emailSender;
        _logger = logger;
        _inspireUser = inspireUser;
        _otpService = otpService;
        _mapper = mapper;
        _configuration = configuration;
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View(new LoginViewModel { ReturnUrl = returnUrl ?? "/" });
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        ViewData["ReturnUrl"] = model.ReturnUrl;
        if (ModelState.IsValid)
        {
             // Check is user valid
             var loginInput = new LoginInputModel { Username = model.Username, Password = model.Password, RememberLogin = model.RememberLogin, ReturnUrl = model.ReturnUrl };
            var validUser = await _inspireUser.ValidateUserAsync(loginInput);
            if (validUser.Status != 2)
            {
                // await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, validUser.Message));
                ModelState.AddModelError(string.Empty, validUser.Message);
                return View(model);
            }

            // Force to reset Password
            if (validUser.ResetDays == 0)
            {
                TempData["userPk"] = validUser.UserPK.ToString();
                TempData["userName"] = validUser.UserName;
                TempData["returnUrl"] = model.ReturnUrl;
                return RedirectToAction(nameof(ChangePassword));
            }

            var ApplicationUser = await _inspireUser.GetApplicationUserAsync(validUser.UserName);
            var isApplicationUser = await _inspireUser.SyncApplicationUserAsync(ApplicationUser, model.Password);
            TempData["UserID"] = ApplicationUser.UserName;
            TempData["UserEmail"] = ApplicationUser.Email;
            TempData["MfaStatus"] = ApplicationUser.MfaStatus;
            ViewData["UserEmail"] = ApplicationUser.Email;

             if (isApplicationUser && ApplicationUser.IsMfaEnabledCompany == "Y" && ApplicationUser.IsMfaEnabledUser && ApplicationUser.MfaStatus == "Pending")
            {
                if (ApplicationUser.MfaType == "AUTHAPP")
                {
                    return RedirectToAction(nameof(EnableAuthenticator), new { returnUrl = model.ReturnUrl }); // Renamed from SetUpAuthApp
                }

                if (ApplicationUser.MfaType == "EMAIL")
                {
                    var user = await _userManager.FindByNameAsync(ApplicationUser.UserName);
                    if (user != null)
                    {
                        var otp = await _otpService.GenerateAndStoreOtp(user.Id);
                        // _emailSender.SendAuthEmail(ApplicationUser.UserName, otp); // Assuming SendAuthEmail exists on concrete type or add it
                         await _emailSender.SendEmailAsync(user.Email!, "OTP", otp);
                        return RedirectToAction(nameof(RegisterEmailOtp), new { returnUrl = model.ReturnUrl });
                    }
                }
               // ModelState.AddModelError("UnKnown", "Unknown MFA Type");
            }

            var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(model.Username);
                if (user != null && user.MustChangePassword)
                {
                    return RedirectToAction(nameof(ChangePassword), new { returnUrl = model.ReturnUrl });
                }

                _logger.LogInformation("User logged in.");
                return LocalRedirect(model.ReturnUrl ?? "/");
            }
             if (result.RequiresTwoFactor && ApplicationUser.IsMfaEnabledUser && ApplicationUser.MfaStatus == "Completed")
            {
                 if (ApplicationUser.MfaType == "EMAIL")
                {
                     var user = await _userManager.FindByNameAsync(ApplicationUser.UserName);
                     if(user != null) {
                        var otp = await _otpService.GenerateAndStoreOtp(user.Id);
                        await _emailSender.SendEmailAsync(user.Email!, "OTP", otp);
                        return RedirectToAction(nameof(VerifyEmailOtp), new { ReturnUrl = model.ReturnUrl, RememberMe = model.RememberLogin });
                     }
                }

                if (ApplicationUser.MfaType == "AUTHAPP")
                {
                    return RedirectToAction(nameof(LoginWith2fa), new { ReturnUrl = model.ReturnUrl, RememberMe = model.RememberLogin }); // VerifyAuthApp maps to standard LoginWith2fa
                }
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                return View("Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }
        }

        // If we got this far, something failed, redisplay form
        return View(model);
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> LoginWith2fa(bool rememberMe, string? returnUrl = null)
    {
        // Ensure the user has gone through the username & password screen first
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

        if (user == null)
        {
            throw new InvalidOperationException("Unable to load two-factor authentication user.");
        }

        var model = new VerifyCodeViewModel { RememberMe = rememberMe, ReturnUrl = returnUrl };
        ViewData["ReturnUrl"] = returnUrl;

        return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LoginWith2fa(VerifyCodeViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            throw new InvalidOperationException("Unable to load two-factor authentication user.");
        }

        var authenticatorCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, model.RememberMe, model.RememberBrowser);

        if (result.Succeeded)
        {
            _logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", user.Id);
            return LocalRedirect(model.ReturnUrl ?? "/");
        }
        else if (result.IsLockedOut)
        {
            _logger.LogWarning("User with ID '{UserId}' account locked out.", user.Id);
            return View("Lockout");
        }
        else
        {
            _logger.LogWarning("Invalid authenticator code entered for user with ID '{UserId}'.", user.Id);
            ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
            return View(model);
        }
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Logout(string? logoutId)
    {
        return View(new LogoutViewModel { LogoutId = logoutId });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout(LogoutViewModel model)
    {
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out.");

        return View("LoggedOut", new LoggedOutViewModel());
    }

    [HttpGet]
    public IActionResult ChangePassword(string? returnUrl = null)
    {
        var vm = new ChangePasswordViewModel { ReturnUrl = returnUrl ?? "/" };
        return View(vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
        if (!changePasswordResult.Succeeded)
        {
            foreach (var error in changePasswordResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // Reset the MustChangePassword flag if it was set
        if (user.MustChangePassword)
        {
            user.MustChangePassword = false;
            await _userManager.UpdateAsync(user);
        }

        await _signInManager.RefreshSignInAsync(user);
        _logger.LogInformation("User changed their password successfully.");

        return View("ChangePasswordSuccess", new PageViewModel { ReturnUrl = model.ReturnUrl });
    }

    // MFA Setup: Enable Authenticator
    [HttpGet]
    public async Task<IActionResult> EnableAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        var model = new AuthenticatorViewModel();
        await LoadSharedKeyAndQrCodeUriAsync(user, model);

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableAuthenticator(AuthCodeViewModel model)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        if (!ModelState.IsValid)
        {
            var vm = new AuthenticatorViewModel();
            await LoadSharedKeyAndQrCodeUriAsync(user, vm);
            return View(vm);
        }

        // Verify the code
        var verificationCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

        if (!is2faTokenValid)
        {
            ModelState.AddModelError("Code", "Verification code is invalid.");
             var vm = new AuthenticatorViewModel();
            await LoadSharedKeyAndQrCodeUriAsync(user, vm);
            return View(vm);
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        var userId = await _userManager.GetUserIdAsync(user);
        _logger.LogInformation("User with ID '{UserId}' has enabled 2FA with an authenticator app.", userId);

        return RedirectToAction(nameof(EnableAuthenticator)); // Or show recovery codes
    }

    private async Task LoadSharedKeyAndQrCodeUriAsync(ApplicationUser user, AuthenticatorViewModel model)
    {
        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(unformattedKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        model.SharedKey = FormatKey(unformattedKey!);

        var email = await _userManager.GetEmailAsync(user);
        model.AuthenticatorUri = GenerateQrCodeUri(email!, unformattedKey!);
    }

    private string FormatKey(string unformattedKey)
    {
        var result = new System.Text.StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
            currentPosition += 4;
        }
        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.Substring(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }

    private string GenerateQrCodeUri(string email, string unformattedKey)
    {
        return string.Format(
            "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6",
            UrlEncoder.Default.Encode("AuthServer.Main"),
            UrlEncoder.Default.Encode(email),
            unformattedKey);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword()
    {
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(PasswordRecoveryViewModel model, string submit)
    {
         if (submit == "ForgotPassword")
        {
             if (string.IsNullOrEmpty(model.UserID))
            {
                ModelState.AddModelError("Question", "User ID should not be blank");
                return View("ForgotPassword");
            }
             // var ApplicationUser = await _inspireUser.GetApplicationUserAsync(model.UserID);
             // Logic adaptation: Reference checks ApplicationUser.UserId != null but effectively it checks if user exists in legacy DB
            var appUser = await _inspireUser.GetApplicationUserAsync(model.UserID);

            if (appUser.UserId != null)
            {
                return RedirectToAction("ForgotPasswordQuestion", new { userId = model.UserID });
            }
            else
            {
                ModelState.AddModelError("Question", "Please choose a question of your choice");
                var vm = await BuildforgotViewModelAsync("", model.UserID.Trim());
                return View("ForgotPassword", vm);
            }
        }
        else
        {
             return Redirect("/"); // RedirectClientUrl
        }
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPasswordQuestion(string userId)
    {
        if (string.IsNullOrEmpty(userId))
        {
            return RedirectToAction("ForgotPassword");
        }
        var vms = await BuildforgotViewModelAsync("", userId.Trim());
        return View(vms);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPasswordQuestion(PasswordRecoveryViewModel model, string submit)
    {
        if (submit == "Cancel")
        {
             return Redirect("/");
        }

        // build a model so we know what to show on the login page
        if (!string.IsNullOrEmpty(model.Question))
        {
            if (!string.IsNullOrEmpty(model.Answer))
            {
                string resetUrl;
                if (Request.IsHttps)
                {
                    resetUrl = string.Format("https://{0}/{1}/{2}", Request.Host.Value, "account", "resetpassword");
                }
                else
                {
                    resetUrl = string.Format("http://{0}/{1}/{2}", Request.Host.Value, "account", "resetpassword");
                }

                ApplicationUser appUser = await _inspireUser.ForgotQAVerification(model, resetUrl);
                string message = appUser.Message ?? "Unknown error";
                long status = appUser.Status;
                if (status == 2)
                {
                    model.Questions = new SelectList(new List<SelectListItem>());
                    model.UserID = "$uccess";
                    return View("ForgotPasswordConfirmation");
                }
                else
                {
                    ModelState.AddModelError("Question", message);
                    var vm = await BuildforgotViewModelAsync("", model.UserID.Trim());
                    return View("ForgotPasswordQuestion", vm);
                }
            }
            else
            {
                ModelState.AddModelError("Answer", "Answer should not be blank");
                var vm = await BuildforgotViewModelAsync("", model.UserID.Trim());
                return View("ForgotPasswordQuestion", vm);
            }
        }
        else
        {
            ModelState.AddModelError("Question", "Please choose a question of your choice");
            var vm = await BuildforgotViewModelAsync("", model.UserID.Trim());
            return View("ForgotPasswordQuestion", vm);
        }
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPasswordConfirmation()
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string? code = null)
    {
        if (code == null)
        {
            return BadRequest("A code must be supplied for password reset.");
        }
        var model = new ResetPasswordViewModel { Code = code };
        return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            // Don't reveal that the user does not exist
            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }
        var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
        if (result.Succeeded)
        {
            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }
        AddErrors(result);
        return View(model);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPasswordConfirmation()
    {
        return View();
    }

    private void AddErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }
}

using System.Net;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using Baic.AuthMain.Models.AccountViewModels;
using Baic.AuthMain.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Extensions;
using Baic.AuthMain.Services;
using Microsoft.Extensions.Localization;
using Baic.AuthMain.Resources;
using System.Reflection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using System.Text.Encodings.Web;
using IdentityServer4.Events;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using static Baic.AuthMain.Models.AccountViewModels.ForgotPasswordViewModel;

namespace Baic.AuthMain.Controllers;

[Authorize]
public class AccountController : Controller
{
    private readonly Fido2Storage _fido2Storage;
    private readonly UserManager<IdentityUserExtended> _userManager;
    private readonly SignInManager<IdentityUserExtended> _signInManager;
    private readonly IInspireUser _inspireUser;
    private readonly ILogger _logger;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IClientStore _clientStore;
    private readonly IPersistedGrantService _persistedGrantService;
    private readonly IStringLocalizer _sharedLocalizer;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IEventService _events;
    private readonly UrlEncoder _urlEncoder;
    private readonly IConfiguration _configuration;
    private readonly OtpService _otpService;
    private readonly EmailSender _emailSender;
    private string RedirectClientUrl;


    public AccountController(
        UserManager<IdentityUserExtended> userManager,
        IPersistedGrantService persistedGrantService,
        SignInManager<IdentityUserExtended> signInManager,
        IInspireUser inspireUser,
        ILoggerFactory loggerFactory,
        IIdentityServerInteractionService interaction,
        IClientStore clientStore,
        IStringLocalizerFactory factory,
        Fido2Storage fido2Storage,
        IAuthenticationSchemeProvider schemeProvider,
        IEventService events,
        UrlEncoder urlEncoder,
         OtpService otpService,
       EmailSender emailSender,
        IConfiguration configuration)

    {
        _fido2Storage = fido2Storage;
        _userManager = userManager;
        _persistedGrantService = persistedGrantService;
        _signInManager = signInManager;
        _inspireUser = inspireUser;
        _logger = loggerFactory.CreateLogger<AccountController>();
        _interaction = interaction;
        _clientStore = clientStore;
        _schemeProvider = schemeProvider;
        _events = events;
        _configuration = configuration;
        _otpService = otpService;
        _emailSender = emailSender;
        var type = typeof(SharedResource);
        var assemblyName = new AssemblyName(type.GetTypeInfo().Assembly.FullName);
        _sharedLocalizer = factory.Create("SharedResource", assemblyName.Name);
        _urlEncoder = urlEncoder;
        RedirectClientUrl = _configuration.GetValue<string>("StsConfig:ClientUrl");
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string returnUrl)

    {
        // build a model so we know what to show on the login page
        var vm = await BuildLoginViewModelAsync(returnUrl);

        if (vm.IsExternalLoginOnly)
        {
            // we only have one option for logging in and it's an external provider
            return ExternalLogin(vm.ExternalProviders.First().AuthenticationScheme, returnUrl);
        }

        return View(vm);
    }

    //
    // POST: /Account/Login
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginInputModel model)
    {
        if (ModelState.IsValid)
        {
            var returnUrl = model.ReturnUrl;
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            var requires2Fa = context?.AcrValues.Count(t => t.Contains("mfa")) >= 1;

            // Check is user valid
            var validUser = await _inspireUser.ValidateUserAsync(model);
            if (validUser.Status != 2)
            {
                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, validUser.Message));
                ModelState.AddModelError(string.Empty, validUser.Message);
                return View(await BuildLoginViewModelAsync(model));
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
                    return RedirectToAction(nameof(SetUpAuthApp), new { returnUrl = model.ReturnUrl });
                }

                if (ApplicationUser.MfaType == "EMAIL")
                {
                    var user = await _userManager.FindByNameAsync(ApplicationUser.UserName);
                    var otp = await _otpService.GenerateAndStoreOtp(user.Id);

                    _emailSender.SendAuthEmail(ApplicationUser.UserName, otp);
                    return RedirectToAction(nameof(RegisterEmailOtp), new { returnUrl = model.ReturnUrl });
                }
                ModelState.AddModelError("UnKnown", "Unknown MFA Type");

            }


            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation(1, "User logged in.");
                    return RedirectToLocal(returnUrl);
                }
                if (result.RequiresTwoFactor && ApplicationUser.IsMfaEnabledUser && ApplicationUser.MfaStatus == "Completed")
                {
                    if (ApplicationUser.MfaType == "EMAIL")
                    {
                        var user = await _userManager.FindByNameAsync(ApplicationUser.UserName);
                        var otp = await _otpService.GenerateAndStoreOtp(user.Id);
                        _emailSender.SendAuthEmail(ApplicationUser.UserName, otp);
                        return RedirectToAction(nameof(VerifyEmailOtp), new { ReturnUrl = returnUrl, RememberMe = model.RememberLogin });
                    }

                    if (ApplicationUser.MfaType == "AUTHAPP")
                    {
                        return RedirectToAction(nameof(VerifyAuthApp), new { ReturnUrl = returnUrl, RememberMe = model.RememberLogin });
                    }
                }

                if (result.IsLockedOut)
                {
                    _logger.LogWarning(2, "User account locked out.");
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, _sharedLocalizer["INVALID_LOGIN_ATTEMPT"]);
                    return View(await BuildLoginViewModelAsync(model));
                }
            }
        }
        // If we got this far, something failed, redisplay form
        return View(await BuildLoginViewModelAsync(model));
    }


    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> SetUpAuthApp(string returnUrl)
    {
        var userId = (string)TempData["UserID"];
        TempData["UserID"] = userId;
        TempData["returnUrl"] = returnUrl;
        var user = await _userManager.FindByNameAsync(userId);
        var vm = await GetAuthenticatorDetailsAsync(user);
        return View(vm);
    }


    [HttpGet]
    [AllowAnonymous]
    public IActionResult VerifyAuthApp(string returnUrl)
    {
        var userId = (string)TempData["UserID"];
        var mfaStatus = (string)TempData["MfaStatus"];
        var vm = new AuthCodeViewModel()
        {
            UserName = userId,
            ReturnUrl = returnUrl,
            MfaStatus = mfaStatus
        };
        return View(vm);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyAuthApp(AuthCodeViewModel AuthCode)
    {
        // check if we are in the context of an authorization request
        var context = await _interaction.GetAuthorizationContextAsync(AuthCode.ReturnUrl);

        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByNameAsync(AuthCode.UserName);

            var verificationCode = AuthCode.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

            var is2FaTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (is2FaTokenValid)
            {
                if (AuthCode.MfaStatus == "Completed")
                {
                    var authenticatorCode = AuthCode.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
                    var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, false, false);

                    if (result != null && result.Succeeded)
                    {
                        await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName));

                        if (context != null)
                        {
                            if (context.IsNativeClient())
                            {
                                // The client is native, so this change in how to
                                // return the response is for better UX for the end user.
                                return this.LoadingPage("Redirect", AuthCode.ReturnUrl);
                            }

                            // we can trust AuthCode.ReturnUrl since GetAuthorizationContextAsync returned non-null
                            return Redirect(AuthCode.ReturnUrl);
                        }

                        // request for a local page
                        if (Url.IsLocalUrl(AuthCode.ReturnUrl))
                        {
                            return Redirect(AuthCode.ReturnUrl);
                        }
                        else if (string.IsNullOrEmpty(AuthCode.ReturnUrl))
                        {
                            return Redirect("~/");
                        }
                        else
                        {
                            // user might have clicked on a malicious link - should be logged
                            throw new Exception("invalid return URL");
                        }
                    }
                    return RedirectToAction(nameof(Login), new { returnUrl = AuthCode.ReturnUrl });
                }
                else
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                    await _inspireUser.UpdateMfaStatusAsync(new MfaStatus() { UserID = user.UserName, MFAStatus = "Completed" });
                    return RedirectToAction(nameof(CompleteAuthAppSetup), new { returnUrl = AuthCode.ReturnUrl });
                }
            }
            else
            {
                ModelState.AddModelError("Invalid Code", "Verification code is invalid.");
            }
        }
        return View(AuthCode);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult VerifyEmailOtp(string returnUrl)
    {
        var userId = (string)TempData["UserID"];
        var mfaStatus = (string)TempData["MfaStatus"];
        var vm = new AuthCodeViewModel()
        {
            UserName = userId,
            ReturnUrl = returnUrl,
            MfaStatus = mfaStatus,
        };
        ViewData["UserEmail"] = (string)TempData["UserEmail"];
        return View(vm);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult RegisterEmailOtp(string returnUrl)
    {
        var userId = (string)TempData["UserID"];
        var mfaStatus = (string)TempData["MfaStatus"];
        var vm = new AuthCodeViewModel()
        {
            UserName = userId,
            ReturnUrl = returnUrl,
            MfaStatus = mfaStatus,
        };
        ViewData["UserEmail"] = (string)TempData["UserEmail"];
        return View(vm);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyEmailOtp(AuthCodeViewModel AuthCode)
    {
        // check if we are in the context of an authorization request
        var context = await _interaction.GetAuthorizationContextAsync(AuthCode.ReturnUrl);

        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByNameAsync(AuthCode.UserName);
            var isOtpValid = await _otpService.VerifyOtp(user.Id, AuthCode.Code);
            ViewData["UserEmail"] = user.Email;
            if (isOtpValid)
            {
                if (AuthCode.MfaStatus == "Completed")
                {
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    var result = await _signInManager.TwoFactorSignInAsync("Email", token, false, false);
                    if (result != null && result.Succeeded)
                    {
                        await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName));

                        if (context != null)
                        {
                            if (context.IsNativeClient())
                            {
                                // The client is native, so this change in how to
                                // return the response is for better UX for the end user.
                                return this.LoadingPage("Redirect", AuthCode.ReturnUrl);
                            }

                            // we can trust AuthCode.ReturnUrl since GetAuthorizationContextAsync returned non-null
                            return Redirect(AuthCode.ReturnUrl);
                        }

                        // request for a local page
                        if (Url.IsLocalUrl(AuthCode.ReturnUrl))
                        {
                            return Redirect(AuthCode.ReturnUrl);
                        }
                        else if (string.IsNullOrEmpty(AuthCode.ReturnUrl))
                        {
                            return Redirect("~/");
                        }
                        else
                        {
                            // user might have clicked on a malicious link - should be logged
                            throw new Exception("invalid return URL");
                        }
                    }
                    return RedirectToAction(nameof(Login), new { returnUrl = AuthCode.ReturnUrl });
                }
                else
                {
                    // OTP is valid, proceed with successful verification
                    await _userManager.ResetAuthenticatorKeyAsync(user);
                    await _userManager.GetAuthenticatorKeyAsync(user);
                    await _userManager.SetTwoFactorEnabledAsync(user, true);

                    await _inspireUser.UpdateMfaStatusAsync(new MfaStatus() { UserID = user.UserName, MFAStatus = "Completed" });
                    return RedirectToAction(nameof(CompleteAuthAppSetup), new { returnUrl = AuthCode.ReturnUrl });
                }

            }
            else
            {
                // OTP is invalid or expired, handle the failed verification
                ModelState.AddModelError("Invalid Code", "Verification code is invalid.");
            }
        }
        return View(AuthCode);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterEmailOtp(AuthCodeViewModel AuthCode)
    {
        // check if we are in the context of an authorization request
        var context = await _interaction.GetAuthorizationContextAsync(AuthCode.ReturnUrl);

        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByNameAsync(AuthCode.UserName);
            var isOtpValid = await _otpService.VerifyOtp(user.Id, AuthCode.Code);
            ViewData["UserEmail"] = user.Email;
            if (isOtpValid)
            {
                if (AuthCode.MfaStatus == "Completed")
                {
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    var result = await _signInManager.TwoFactorSignInAsync("Email", token, false, false);
                    if (result != null && result.Succeeded)
                    {
                        await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName));

                        if (context != null)
                        {
                            if (context.IsNativeClient())
                            {
                                // The client is native, so this change in how to
                                // return the response is for better UX for the end user.
                                return this.LoadingPage("Redirect", AuthCode.ReturnUrl);
                            }

                            // we can trust AuthCode.ReturnUrl since GetAuthorizationContextAsync returned non-null
                            return Redirect(AuthCode.ReturnUrl);
                        }

                        // request for a local page
                        if (Url.IsLocalUrl(AuthCode.ReturnUrl))
                        {
                            return Redirect(AuthCode.ReturnUrl);
                        }
                        else if (string.IsNullOrEmpty(AuthCode.ReturnUrl))
                        {
                            return Redirect("~/");
                        }
                        else
                        {
                            // user might have clicked on a malicious link - should be logged
                            throw new Exception("invalid return URL");
                        }
                    }
                    return RedirectToAction(nameof(Login), new { returnUrl = AuthCode.ReturnUrl });
                }
                else
                {
                    // OTP is valid, proceed with successful verification
                    await _userManager.ResetAuthenticatorKeyAsync(user);
                    await _userManager.GetAuthenticatorKeyAsync(user);
                    await _userManager.SetTwoFactorEnabledAsync(user, true);

                    await _inspireUser.UpdateMfaStatusAsync(new MfaStatus() { UserID = user.UserName, MFAStatus = "Completed" });
                    return RedirectToAction(nameof(CompleteAuthAppSetup), new { returnUrl = AuthCode.ReturnUrl });
                }

            }
            else
            {
                // OTP is invalid or expired, handle the failed verification
                ModelState.AddModelError("Invalid Code", "Verification code is invalid.");
            }
        }
        return View(AuthCode);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult CompleteAuthAppSetup(string returnUrl)
    {
        return View();
    }

    //
    // GET: /Account/ChangePassword
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ChangePassword(string returnUrl = null)
    {
        var vm = new ChangePasswordViewModel();
        vm.userPK = Convert.ToInt64(TempData["userPk"]);
        vm.UserId = (string)TempData["userName"];
        vm.ReturnUrl = (string)TempData["returnUrl"];
        return View(vm);
    }

    //
    // POST: /Account/ChangePassword
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model, string returnUrl = null)
    {
        _logger.LogInformation("Account Controller - ChangePassword - Start - {0}", model.UserId);
        ViewData["ReturnUrl"] = returnUrl;

        if (ModelState.IsValid)
        {
            var IsPasswordUpdated = await _inspireUser.UpdatePasswordAsync(model);

            if (IsPasswordUpdated.Status == 2)
            {
                _logger.LogInformation("Account Controller - ChangePassword - End - {0}", "Success");
                return RedirectToAction(nameof(ChangePasswordSuccess), new { returnUrl = model.ReturnUrl });

            }
            else
            {
                _logger.LogInformation("Account Controller - ChangePassword - End - Invalid Password {0}", IsPasswordUpdated.Message);
                ModelState.AddModelError("Invalid Password", IsPasswordUpdated.Message);
            }
        }

        // If we got this far, something failed, redisplay form
        return View(model);
    }

    //
    // GET: /Account/ChangePasswordSuccess
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ChangePasswordSuccess(string returnUrl = null)
    {
        var vm = new PageViewModel()
        {
            ReturnUrl = returnUrl
        };

        return View(vm);
    }



    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Logout(string logoutId)
    {
        // build a model so the logout page knows what to display
        var vm = await BuildLogoutViewModelAsync(logoutId);

        if (vm.ShowLogoutPrompt == false)
        {
            // if the request for logout was properly authenticated from IdentityServer, then
            // we don't need to show the prompt and can just log the user out directly.
            return await Logout(vm);
        }
        return View(vm);
    }

    /// <summary>
    /// Handle logout page postback
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout(LogoutViewModel model)
    {
        var idp = User?.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;

        if (idp == null)
        {
            return RedirectToAction(nameof(Login));
        }

        var subjectId = HttpContext.User.Identity.GetSubjectId();

        if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
        {
            if (model.LogoutId == null)
            {
                // if there's no current logout context, we need to create one
                // this captures necessary info from the current logged in user
                // before we signout and redirect away to the external IdP for signout
                model.LogoutId = await _interaction.CreateLogoutContextAsync();
            }

            // string url = "/Account/Logout?logoutId=" + model.LogoutId;
            try
            {
                await _signInManager.SignOutAsync();
                // await HttpContext.Authentication.SignOutAsync(idp, new AuthenticationProperties { RedirectUri = url });
            }
            catch (NotSupportedException)
            {
            }
        }

        // delete authentication cookie
        await _signInManager.SignOutAsync();

        // set this so UI rendering sees an anonymous user
        HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity());

        // get context information (client name, post logout redirect URI and iframe for federated signout)
        var logout = await _interaction.GetLogoutContextAsync(model.LogoutId);

        var vm = new LoggedOutViewModel
        {
            AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
            PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
            ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
            SignOutIframeUrl = logout?.SignOutIFrameUrl,
            LogoutId = model.LogoutId
        };


        await _persistedGrantService.RemoveAllGrantsAsync(subjectId, "angular2client");

        return View("LoggedOut", vm);
    }


    //
    // POST: /Account/ExternalLogin
    //[ValidateAntiForgeryToken]
    [HttpPost]
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ExternalLogin(string provider, string returnUrl = null)
    {
        // Request a redirect to the external login provider.
        var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Challenge(properties, provider);
    }

    //
    // GET: /Account/ExternalLoginCallback
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        var requires2Fa = context?.AcrValues.Count(t => t.Contains("mfa")) >= 1;

        if (remoteError != null)
        {
            ModelState.AddModelError(string.Empty, _sharedLocalizer["EXTERNAL_PROVIDER_ERROR", remoteError]);
            return View(nameof(Login));
        }
        var info = await _signInManager.GetExternalLoginInfoAsync();

        if (info == null)
        {
            return RedirectToAction(nameof(Login));
        }

        var email = info.Principal.FindFirstValue(ClaimTypes.Email);


        // Sign in the user with this external login provider if the user already has a login.
        var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
        if (result.Succeeded)
        {
            _logger.LogInformation(5, "User logged in with {Name} provider.", info.LoginProvider);
            return RedirectToLocal(returnUrl);
        }

        if (result.IsLockedOut)
        {
            return View("Lockout");
        }
        else
        {
            // If the user does not have an account, then ask the user to create an account.
            ViewData["ReturnUrl"] = returnUrl;
            ViewData["LoginProvider"] = info.LoginProvider;
            //var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email });
        }
    }

    //
    // POST: /Account/ExternalLoginConfirmation
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null, string loginProvider = null)
    {
        if (ModelState.IsValid)
        {
            // Get the information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return View("ExternalLoginFailure");
            }
            var user = new IdentityUserExtended { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                result = await _userManager.AddLoginAsync(user, info);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation(6, "User created an account using {Name} provider.", info.LoginProvider);
                    return RedirectToLocal(returnUrl);
                }
            }
            AddErrors(result);
        }

        ViewData["ReturnUrl"] = returnUrl;
        ViewData["LoginProvider"] = loginProvider;
        return View(model);
    }

    // GET: /Account/ConfirmEmail
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string userId, string code)
    {
        if (userId == null || code == null)
        {
            return View("Error");
        }
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return View("Error");
        }
        code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
        var result = await _userManager.ConfirmEmailAsync(user, code);
        return View(result.Succeeded ? "ConfirmEmail" : "Error");
    }

    //
    // GET: /Account/ForgotPassword
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword()
    {
        return View();
    }

    // POST: /Account/ForgotPassword
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(PasswordRecoveryViewModel model, string submit)
    {
        ApplicationUser applicationUser = new ApplicationUser();
        if (submit == "ForgotPassword")
        {
            var ApplicationUser = await _inspireUser.GetApplicationUserAsync(model.UserID);

            if (string.IsNullOrEmpty(model.UserID))
            {
                ModelState.AddModelError("Question", "User ID should not be blank");
                return View("ForgotPassword");
            }

            if (ApplicationUser.UserId != null)
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
            return Redirect(RedirectClientUrl);
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
            return Redirect(RedirectClientUrl);
        }
        ApplicationUser applicationUser = new ApplicationUser();
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
                string message = appUser.Message;
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

    /// <summary>
    /// Entry point into the ResetPassword workflow
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword(string token, string redirect_uri)
    {
        // build a model so we know what to show on the login page
        var vm = await BuildResetViewModelAsync(token, redirect_uri);
        if (vm.ErrorMessage == "Success")
        {
            vm.ErrorMessage = null;
        }
        else if (!string.IsNullOrEmpty(vm.ErrorMessage))
        {
            ModelState.AddModelError("Password", vm.ErrorMessage);
        }

        if (vm.IsPasswordQuestions == true)
        {
            return View("NewLoginResetPassword", vm);
        }
        else
        {
            return View("ResetPassword", vm);
        }
    }

    //
    // GET: /Account/ForgotPasswordConfirmation
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPasswordConfirmation()
    {
        return View();
    }

    //
    // GET: /Account/ResetPassword
    [HttpGet]
    [AllowAnonymous]
    private async Task<ResetPasswordViewModel> BuildResetViewModelAsync(string token, string returnUrl)
    {
        var result = new ResetPasswordViewModel();
        if (!string.IsNullOrEmpty(token))
        {
            result = await _inspireUser.PwdTokenVerification(token, returnUrl);
        }
        return result;
    }

    //
    // POST: /Account/ResetPassword
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        _logger.LogInformation("Account Controller - Reset Password - Start - userid - {0}", model);
        // build a model so we know what to show on the login page
        if (ModelState.IsValid)
        {
            ApplicationUser res = await _inspireUser.ResetPassword(model);
            string message = res.Message;
            long status = res.Status;
            if (status == 2)
            {
                _logger.LogInformation("Account Controller - Reset Password - End - {0}", "Success");
                // Todo: Redirect to Client redirectUri
                return Redirect(RedirectClientUrl);
            }
            else
            {
                _logger.LogInformation("Account Controller - Reset Password - End - Fail - {0}", message);
                ModelState.AddModelError("Password", message);
                if (model.IsPasswordQuestions == true)
                {
                    return View("NewLoginResetPassword", model);
                }
                else
                {
                    return View("ResetPassword", model);
                }
            }
        }
        else
        {
            _logger.LogInformation("Account Controller - Reset Password - End - {0}", "Fail Model Invalid");
            if (model.IsPasswordQuestions == true)
            {
                return View("NewLoginResetPassword", model);
            }
            else
            {
                return View("ResetPassword", model);
            }
        }
    }

    //
    // GET: /Account/ResetPasswordConfirmation
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPasswordConfirmation()
    {
        return View();
    }


    /// <summary>
    /// Entry point into the ResetPassword workflow
    /// </summary>
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> NewLoginResetPassword(string token, string redirect_uri)
    {
        // build a model so we know what to show on the login page
        var vm = await BuildResetViewModelAsync(token, redirect_uri);
        if (vm.ErrorMessage == "Success")
        {
            vm.ErrorMessage = null;
        }
        return View("NewLoginResetPassword", vm);
    }

    //
    // POST: /Account/ResetPassword
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> NewLoginResetPassword(ResetPasswordViewModel model)
    {
        // build a model so we know what to show on the login page
        _logger.LogInformation("Account Controller - NewLoginResetPassword - Start - UserId - {0}", model.UserId);
        if (ModelState.IsValid)
        {
            ApplicationUser res = await _inspireUser.ResetPassword(model);
            string message = res.Message;
            long status = res.Status;
            if (status == 2)
            {
                _logger.LogInformation("Account Controller - NewLoginResetPassword - End - {0}", "Success");
                // Todo: Redirect to Client redirectUri
                return Redirect(RedirectClientUrl);
            }
            else
            {
                _logger.LogInformation("Account Controller - NewLoginResetPassword - End - {0}", message);
                model.ErrorMessage = message;
                return View("NewLoginResetPassword", model);
            }
        }
        else
        {
            _logger.LogInformation("Account Controller - NewLoginResetPassword - End - {0}", "Model Invalid");
            return View("NewLoginResetPassword", model);
        }
    }

    //
    // GET: /Account/ResetPasswordConfirmation
    [HttpGet]
    [AllowAnonymous]
    public IActionResult NewLoginResetPassword()
    {
        return View();
    }

    //
    // GET: /Account/SendCode
    [HttpGet]
    [AllowAnonymous]
    public async Task<ActionResult> SendCode(string returnUrl = null, bool rememberMe = false)
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return View("Error");
        }
        var userFactors = await _userManager.GetValidTwoFactorProvidersAsync(user);
        var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
        return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
    }



    private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

            // this is meant to short circuit the UI and only trigger the one external IdP
            var vm = new LoginViewModel
            {
                EnableLocalLogin = local,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
            };

            if (!local)
            {
                vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
            }

            return vm;
        }

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ExternalProvider
            {
                DisplayName = x.DisplayName ?? x.Name,
                AuthenticationScheme = x.Name
            }).ToList();

        var allowLocal = true;
        if (context?.Client.ClientId != null)
        {
            var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
            if (client != null)
            {
                allowLocal = client.EnableLocalLogin;

                if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                {
                    providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                }
            }
        }

        return new LoginViewModel
        {
            AllowRememberLogin = AccountOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
            ReturnUrl = returnUrl,
            Username = context?.LoginHint,
            ExternalProviders = providers.ToArray()
        };
    }

    private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
    {
        var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
        vm.Username = model.Username;
        vm.RememberLogin = model.RememberLogin;
        return vm;
    }

    private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
    {
        var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

        if (User?.Identity.IsAuthenticated != true)
        {
            // if the user is not authenticated, then just show logged out page
            vm.ShowLogoutPrompt = false;
            return vm;
        }

        var context = await _interaction.GetLogoutContextAsync(logoutId);
        if (context?.ShowSignoutPrompt == false)
        {
            // it's safe to automatically sign-out
            vm.ShowLogoutPrompt = false;
            return vm;
        }

        // show the logout prompt. this prevents attacks where the user
        // is automatically signed out by another malicious web page.
        return vm;
    }

    private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
    {
        // get context information (client name, post logout redirect URI and iframe for federated signout)
        var logout = await _interaction.GetLogoutContextAsync(logoutId);

        var vm = new LoggedOutViewModel
        {
            AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
            PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
            ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
            SignOutIframeUrl = logout?.SignOutIFrameUrl,
            LogoutId = logoutId
        };

        if (User?.Identity.IsAuthenticated == true)
        {
            var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
            if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
            {
                var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                if (providerSupportsSignout)
                {
                    if (vm.LogoutId == null)
                    {
                        // if there's no current logout context, we need to create one
                        // this captures necessary info from the current logged in user
                        // before we signout and redirect away to the external IdP for signout
                        vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                    }

                    vm.ExternalAuthenticationScheme = idp;
                }
            }
        }

        return vm;
    }

    private async Task<PasswordRecoveryViewModel> BuildforgotViewModelAsync(string returnUrl, string userId)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

        ForgetPasswordModel pwdModel = await _inspireUser.GetQuestionsByUserId(userId);
        var listItems = pwdModel.Questions.Select(a => new SelectListItem() { Text = a.QuestionText, Value = a.AnswerId });


        return new PasswordRecoveryViewModel()
        {
            UserID = userId,
            Email = pwdModel.EmailId,
            Questions = new SelectList(listItems, "Value", "Text"),
            ReturnUrl = returnUrl
        };
    }
    #region Helpers

    private void AddErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }

    private IActionResult RedirectToLocal(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        else
        {
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }

    private async Task<AuthenticatorViewModel> GetAuthenticatorDetailsAsync(IdentityUserExtended user)
    {
        // Load the authenticator key & QR code URI to display on the form
        await _userManager.ResetAuthenticatorKeyAsync(user);
        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);

        var email = await _userManager.GetEmailAsync(user);
        var userId = await _userManager.GetUserNameAsync(user);

        return new AuthenticatorViewModel
        {
            SharedKey = FormatKey(unformattedKey),
            AuthenticatorUri = GenerateQrCodeUri(userId, email, unformattedKey)
        };
    }

    private string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
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

    private string GenerateQrCodeUri(string userId, string email, string unformattedKey)
    {
        const string AuthenticatorUriFormat = "otpauth://totp/BAIC%20Local%20Portal:{0}?issuer={2}&secret={3}&digits=6";

        return string.Format(
        AuthenticatorUriFormat,
            _urlEncoder.Encode(userId),
            _urlEncoder.Encode(email),
            _urlEncoder.Encode(_configuration.GetSection("StsConfig")["ClientEnv"]),
            unformattedKey);
    }



    #endregion
}
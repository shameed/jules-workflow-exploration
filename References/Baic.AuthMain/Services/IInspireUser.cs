using Baic.AuthMain.Models;
using Baic.AuthMain.Models.AccountViewModels;
using System.Collections.Generic;
using System.Threading.Tasks;
using static Baic.AuthMain.Models.AccountViewModels.ForgotPasswordViewModel;

namespace Baic.AuthMain.Services
{
    public interface IInspireUser
    {
        Task<ResultModel<List<BusinessFunctionModel>>> GetAdditionalUserClaimsAsync(string userId, DefaultParameters defaultParams);
        Task<ApplicationUser> GetApplicationUserAsync(string userName);
        Task<bool> SyncApplicationUserAsync(ApplicationUser appUser, string password);
        Task<ResultModel<bool>> UpdatePasswordAsync(ChangePasswordViewModel model);
        Task<SyncUser> ValidateUserAsync(LoginInputModel model);
        Task<ForgetPasswordModel> GetQuestionsByUserId(string userId);
        Task<ApplicationUser> ForgotQAVerification(PasswordRecoveryViewModel forgotPwdVM, string resetUrl);
        Task<ResetPasswordViewModel> PwdTokenVerification(string token, string returnUrl);
        Task<ApplicationUser> ResetPassword(ResetPasswordViewModel model);
        Task<ResultModel<object>> UpdateMfaStatusAsync(MfaStatus mfaStatus);
    }
}
using Dapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Baic.AuthMain.Models;
using Baic.AuthMain.Models.AccountViewModels;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using Newtonsoft.Json.Linq;
using static Baic.AuthMain.Models.AccountViewModels.ForgotPasswordViewModel;
using static IdentityServer4.Models.IdentityResources;
using Baic.AuthMain.Common;
using System.Net.NetworkInformation;
using System.Reflection.Metadata;
using Baic.AuthMain.Resources;

namespace Baic.AuthMain.Services;

public class InspireUser : IInspireUser
{
    private readonly UserManager<IdentityUserExtended> _userManager;
    private readonly IConfiguration _config;
    private readonly IHttpClientFactory _clientFactory;
    private readonly IMapper _mapper;
    private readonly IEmailSender _emailSender;

    private IDbConnection InspireDbConn
    {
        get
        {
            return new SqlConnection(_config.GetConnectionString("SimpleInspireDB"));
        }
    }

    public InspireUser(UserManager<IdentityUserExtended> userManager, IConfiguration configuration, IHttpClientFactory clientFactory, IMapper mapper, IEmailSender emailSender)
    {
        _userManager = userManager;
        _config = configuration;
        _clientFactory = clientFactory;
        _mapper = mapper;
        _emailSender = emailSender;
    }

    public async Task<ApplicationUser> GetApplicationUserAsync(string userName)
    {
        var ApplicationUser = new ApplicationUser();

        try
        {
            using (IDbConnection connection = InspireDbConn)
            {
                connection.Open();
                var parameters = new DynamicParameters();
                parameters.Add("@UserID", userName, DbType.String, ParameterDirection.Input, 50);
                parameters.Add("@Status", dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
                parameters.Add("@ErrorMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);

                var result = connection.Query<InspireUserModel>("SI_USR_GetUserDetails", parameters, commandType: CommandType.StoredProcedure).FirstOrDefault();



                if (result != null)
                {
                    ApplicationUser.UserName = result.ASUserId;
                    ApplicationUser.Email = result.Email;
                    ApplicationUser.UserPk = result.ASUserPk;
                    ApplicationUser.UserId = result.ASUserId;
                    ApplicationUser.UserType = result.Type;
                    ApplicationUser.Language = result.Language;
                    ApplicationUser.EditVersion = result.Logged;
                    ApplicationUser.AuthType = result.AuthType;
                    ApplicationUser.DiaryDisplayDays = result.DiaryDisplayDays;
                    ApplicationUser.IsBankIcon = result.IsBankIcon;
                    ApplicationUser.IsHelpDesk = result.IsHelpDesk;
                    ApplicationUser.IsUnderwriter = result.IsUnderwriter;
                    ApplicationUser.IsInspection = result.IsInspection;
                    ApplicationUser.FirstName = result.FirstName;
                    ApplicationUser.LastName = result.LastName;
                    ApplicationUser.AnchorPage = result.AnchorPage;
                    ApplicationUser.UserClientPk = result.UserClientPk;
                    ApplicationUser.IsMfaEnabledCompany = result.IsMfaEnabledCompany;
                    ApplicationUser.IsMfaEnabledUser = result.IsMfaEnabledUser;
                    ApplicationUser.MfaType = result.MfaType;
                    ApplicationUser.MfaStatus = result.MfaStatus;
                    ApplicationUser.Status = parameters.Get<Int16>("Status");
                    ApplicationUser.Message = parameters.Get<string>("ErrorMessage");
                }
                else
                {
                    ApplicationUser.Status = parameters.Get<Int16>("Status");
                    ApplicationUser.Message = parameters.Get<string>("ErrorMessage");
                }

            }

            return await Task.Run(() => ApplicationUser);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }

    }

    public async Task<bool> SyncApplicationUserAsync(ApplicationUser appUser, string password)
    {
        IdentityResult result = null;
        var identityUser = await _userManager.FindByNameAsync(appUser.UserName);
        if (identityUser != null)
        {
            result = await _userManager.RemovePasswordAsync(identityUser);
            if (result.Succeeded)
            {
                var emailUpdateResult = await _userManager.SetEmailAsync(identityUser, appUser.Email);
                if (emailUpdateResult.Succeeded)
                {
                    result = await _userManager.AddPasswordAsync(identityUser, password);
                }
            }
        }
        else
        {
            var newIdentityUser = new IdentityUserExtended
            {
                Id = Guid.NewGuid().ToString(),
                UserName = appUser.UserName,
                Email = appUser.Email,
                UserPk = appUser.UserPk,
                UserId = appUser.UserId,
                UserType = appUser.UserType,
                Language = appUser.Language
            };
            result = await _userManager.CreateAsync(newIdentityUser, password);
        }
        return result.Succeeded;
    }

    public async Task<SyncUser> ValidateUserAsync(LoginInputModel model)
    {
        SyncUser result = null;
        try
        {
            using (var sha256 = SHA256.Create())
            {
                model.Password = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(model.Password)));
            }

            using (IDbConnection connection = InspireDbConn)
            {
                connection.Open();
                var parameters = new DynamicParameters();
                parameters.AddDynamicParams(new { UserID = model.Username, UserPassword = model.Password, Language = "English" });
                parameters.Add("@UserPK", dbType: DbType.Int64, direction: ParameterDirection.Output, size: 1);
                parameters.Add("@ActiveDays", dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
                parameters.Add("@ResetDays", dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
                parameters.Add("@Status", dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
                parameters.Add("@ErrorMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);

                connection.Query("SI_USR_Login", parameters, commandType: CommandType.StoredProcedure);

                var status = parameters.Get<Int16>("Status");
                var message = parameters.Get<string>("ErrorMessage");
                long userPk = parameters.Get<Int64>("UserPK");
                int activeDays = parameters.Get<Int16>("ActiveDays");
                int resetDays = parameters.Get<Int16>("ResetDays");
                if (status == 2)
                {
                    result = new SyncUser()
                    {
                        UserPK = userPk,
                        UserName = model.Username,
                        ActiveDays = activeDays,
                        ResetDays = resetDays,
                        Status = status,
                        Message = message
                    };

                }
                else
                {
                    result = new SyncUser()
                    {
                        UserName = model.Username,
                        Status = status,
                        Message = message
                    };

                }
            }

        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }


        return await Task.Run(() => result);
    }

    public async Task<ResultModel<bool>> UpdatePasswordAsync(ChangePasswordViewModel model)
    {

        var result = new ResultModel<bool>();
        try
        {
            using (var sha256 = SHA256.Create())
            {
                model.CurrentPassword = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(model.CurrentPassword)));
                model.NewPassword = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(model.NewPassword)));
            }

            using (IDbConnection connection = InspireDbConn)
            {
                connection.Open();
                var parameters = new DynamicParameters();
                parameters.Add("@UserPK", model.userPK);
                parameters.Add("@UserId", model.UserId);
                parameters.Add("@CurrentPassword", model.CurrentPassword);
                parameters.Add("@NewPassword", model.NewPassword);
                parameters.Add("@Status", dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
                parameters.Add("@ErrorMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);

                connection.Query("SI_USR_MFAChanagePassword", parameters, commandType: CommandType.StoredProcedure);

                result = new ResultModel<bool>()
                {
                    Status = parameters.Get<Int16>("Status"),
                    Message = parameters.Get<string>("ErrorMessage"),
                    Data = true
                };
            }
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }

        return await Task.Run(() => result);
    }

    public async Task<ResultModel<List<BusinessFunctionModel>>> GetAdditionalUserClaimsAsync(string userId, DefaultParameters defaultParameters)
    {
        var result = new ResultModel<List<BusinessFunctionModel>>();
        try
        {
            using (IDbConnection connection = InspireDbConn)
            {
                connection.Open();
                var parameters = new DynamicParameters(defaultParameters);
                parameters.Add("@ASUserId", userId, DbType.String, ParameterDirection.Input, 50);
                parameters.Add("@Status", dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
                parameters.Add("@ErrorMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);
                List<BusinessFunctionModel> userBizFuns = connection.Query<BusinessFunctionModel>("SI_USR_BusinessFunctions", parameters, commandType: CommandType.StoredProcedure).ToList();

                if (userBizFuns != null)
                {
                    result.Data = userBizFuns;
                    result.Status = parameters.Get<Int16>("Status");
                    result.Message = parameters.Get<string>("ErrorMessage");
                }
                else
                {
                    result.Data = null;
                    result.Status = parameters.Get<Int16>("Status");
                    result.Message = parameters.Get<string>("ErrorMessage");
                }

            }

            return await Task.Run(() => result);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public async Task<ApplicationUser> ForgotQAVerification(PasswordRecoveryViewModel forgotPwdVM, string resetUrl)
    {
        var ApplicationUser = new ApplicationUser();
        var questions = new List<QuestionAnswerDM>();

        if (forgotPwdVM.ReturnUrl == null)
        {
            forgotPwdVM.ReturnUrl = "";
        }

        var answer = new Answer()
        {
            AnswerText = forgotPwdVM.Answer,
            AnswerId = forgotPwdVM.Question,
            Referrer = resetUrl,
            ReturnUrl = forgotPwdVM.ReturnUrl
        };

        bool isValid = false;
        try
        {
            using (IDbConnection connection = InspireDbConn)
            {
                connection.Open();
                var parameters = new DynamicParameters();
                parameters.Add("@UserID", forgotPwdVM.UserID, DbType.String, ParameterDirection.Input, 50);
                parameters.Add("@OutEmail", dbType: DbType.String, direction: ParameterDirection.Output, size: 60);
                parameters.Add("@Status", dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
                parameters.Add("@ErrorMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);

                questions = connection.Query<QuestionAnswerDM>("SI_USR_QuestionsAnswers", parameters, commandType: CommandType.StoredProcedure).ToList();

                List<QuestionsAnswer> questionAnswer = _mapper.Map<List<QuestionsAnswer>>(questions);

                string answerEnrolled = questionAnswer.SingleOrDefault(a => a.AnswerId.Equals(answer.AnswerId, StringComparison.OrdinalIgnoreCase)).AnswerText.ToLower().Trim();
                isValid = false;
                if (answerEnrolled.Equals(answer.AnswerText.ToLower().Trim()))
                {
                    isValid = true;
                }

                ApplicationUser.Status = parameters.Get<Int16>("Status");
                ApplicationUser.Message = parameters.Get<string>("ErrorMessage");
                ApplicationUser.Email = parameters.Get<string>("OutEmail");
            }
            Int64 emailLogPk = 0;
            using (IDbConnection connection = InspireDbConn)
            {
                connection.Open();
                var parameters = new DynamicParameters();
                parameters.Add("@UserID", forgotPwdVM.UserID, DbType.String, ParameterDirection.Input, 50);
                parameters.Add("@Referrer", answer.Referrer, dbType: DbType.String, direction: ParameterDirection.Input, size: 2048);
                parameters.Add("@IsValidAnswer", isValid, dbType: DbType.Boolean, direction: ParameterDirection.Input, size: 50);
                parameters.Add("@ReturnUrl", answer.ReturnUrl, dbType: DbType.String, direction: ParameterDirection.Input, size: 500);
                parameters.Add("@Status", dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
                parameters.Add("@ErrorMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);
                parameters.Add("@AsEmailLogPk", dbType: DbType.Int64, direction: ParameterDirection.Output, size: 18);

                connection.Query("SI_USR_ForgotPassword", parameters, commandType: CommandType.StoredProcedure);

                ApplicationUser.Status = parameters.Get<Int16>("Status");
                ApplicationUser.Message = parameters.Get<string>("ErrorMessage");
                emailLogPk = parameters.Get<Int64>("AsEmailLogPk");

                if (emailLogPk != 0)
                {
                    await _emailSender.TriggerMail(emailLogPk);
                }
            }

            return await Task.Run(() => ApplicationUser);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public async Task<ForgetPasswordModel> GetQuestionsByUserId(string userId)
    {
        var ApplicationUser = new ApplicationUser();
        var qustionanswers = new List<QuestionAnswerDM>();
        using (IDbConnection connection = InspireDbConn)
        {
            connection.Open();
            var parameters = new DynamicParameters();
            parameters.Add("@UserID", userId, DbType.String, ParameterDirection.Input, 50);
            parameters.Add("@OutEmail", dbType: DbType.String, direction: ParameterDirection.Output, size: 60);
            parameters.Add("@Status", dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
            parameters.Add("@ErrorMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);

            qustionanswers = connection.Query<QuestionAnswerDM>("SI_USR_QuestionsAnswers", parameters, commandType: CommandType.StoredProcedure).ToList();
            List<Question> questions = _mapper.Map<List<Question>>(qustionanswers);


            ForgetPasswordModel result = new ForgetPasswordModel();
            result.UserId = userId;
            result.EmailId = parameters.Get<string>("OutEmail");
            result.Questions = questions;
            return result;

        }
    }
    public async Task<ResetPasswordViewModel> PwdTokenVerification(string token, string returnUrl)
    {
        ResetPasswordViewModel resetPasswordModel = new ResetPasswordViewModel();
        var ApplicationUser = new ApplicationUser();
        var questions = new List<QuestionAnswerDM>();

        string userId = string.Empty;
        string password = string.Empty;
        bool isPasswordQuestions = false;
        string outEmail = string.Empty;

        using (IDbConnection connection = InspireDbConn)
        {
            connection.Open();
            var parameters = new DynamicParameters();
            parameters.Add(Constants.fbwdlink, token, DbType.String, ParameterDirection.Input, 250);
            parameters.Add(Constants.outuserIdDbParameter, dbType: DbType.String, direction: ParameterDirection.Output, size: 100);
            parameters.Add(Constants.outuserPasswordDbParameter, dbType: DbType.String, direction: ParameterDirection.Output, size: 250);
            parameters.Add(Constants.outIsPasswordQuestionsDbParameter, dbType: DbType.Boolean, direction: ParameterDirection.Output, size: 1);
            parameters.Add(Constants.statusDbParam, dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
            parameters.Add(Constants.errMsgDbParam, dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);

            connection.Query<ResetPasswordViewModel>("SI_USR_ForgotPWDLink", parameters, commandType: CommandType.StoredProcedure).FirstOrDefault();

            resetPasswordModel.UserId = parameters.Get<string>(Constants.outuserId);
            resetPasswordModel.ReturnUrl = returnUrl;
            resetPasswordModel.IsPasswordQuestions = parameters.Get<bool>(Constants.outIsPasswordQuestions);

            userId = parameters.Get<string>(Constants.outuserId);
            password = parameters.Get<string>(Constants.outuserPassword);
            isPasswordQuestions = parameters.Get<bool>(Constants.outIsPasswordQuestions);
            ApplicationUser.Status = parameters.Get<Int16>("Status");
            resetPasswordModel.ErrorMessage = parameters.Get<string>("ErrorMessage");
        }

        if (ApplicationUser.Status == 2)
        {
            using (IDbConnection connection = InspireDbConn)
            {
                connection.Open();
                var parameters = new DynamicParameters();
                parameters.Add(Constants.userIdDbParameter, userId, dbType: DbType.String, direction: ParameterDirection.Input, size: 50);
                parameters.Add(Constants.outEmaildbParameter, dbType: DbType.String, direction: ParameterDirection.Output, size: 60);
                parameters.Add(Constants.statusDbParam, dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
                parameters.Add(Constants.errMsgDbParam, dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);

                questions = connection.Query<QuestionAnswerDM>("SI_USR_QuestionsAnswers", parameters, commandType: CommandType.StoredProcedure).ToList();

                ApplicationUser.Status = parameters.Get<Int16>("Status");
                resetPasswordModel.ErrorMessage = parameters.Get<string>("ErrorMessage");
                outEmail = parameters.Get<string>(Constants.outEmail);
            }

            if (ApplicationUser.Status == 2)
            {
                List<QuestionsAnswer> qNa = _mapper.Map<List<QuestionsAnswer>>(questions);

                if (qNa.Count > 0)
                {
                    resetPasswordModel.Question1 = qNa.FirstOrDefault(a => a.QuestionId.Equals("Question1", StringComparison.OrdinalIgnoreCase)).QuestionText;
                    resetPasswordModel.Question2 = qNa.FirstOrDefault(a => a.QuestionId.Equals("Question2", StringComparison.OrdinalIgnoreCase)).QuestionText;
                    resetPasswordModel.Question3 = qNa.FirstOrDefault(a => a.QuestionId.Equals("Question3", StringComparison.OrdinalIgnoreCase)).QuestionText;
                    resetPasswordModel.Answer1 = qNa.FirstOrDefault(a => a.AnswerId.Equals("Answer1", StringComparison.OrdinalIgnoreCase)).AnswerText;
                    resetPasswordModel.Answer2 = qNa.FirstOrDefault(a => a.AnswerId.Equals("Answer2", StringComparison.OrdinalIgnoreCase)).AnswerText;
                    resetPasswordModel.Answer3 = qNa.FirstOrDefault(a => a.AnswerId.Equals("Answer3", StringComparison.OrdinalIgnoreCase)).AnswerText;
                }
            }
        }
        return resetPasswordModel;
    }

    public async Task<ApplicationUser> ResetPassword(ResetPasswordViewModel model)
    {
        ApplicationUser result = new ApplicationUser();
        using (IDbConnection connection = InspireDbConn)
        {
            InspireDbConn.Open();
            var parameters = new DynamicParameters();
            var resetPasswordDM = _mapper.Map<ResetPasswordDM>(model);
            parameters.AddDynamicParams(resetPasswordDM);
            parameters.Add(Constants.statusDbParam, dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
            parameters.Add(Constants.errMsgDbParam, dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);



            await InspireDbConn.QueryAsync("SI_USR_ResetPassword", parameters, commandType: CommandType.StoredProcedure);

            result.Status = parameters.Get<Int16>("Status");
            result.Message = parameters.Get<string>("ErrorMessage");



            return result;
        }
    }
    public async Task<ResultModel<object>> UpdateMfaStatusAsync(MfaStatus mfaStatus)
    {
        return await Task.Run(() => UpdateMfaStatus(mfaStatus));
    }

    private ResultModel<object> UpdateMfaStatus(MfaStatus mfaStatus)
    {

        ResultModel<object> result = null;
        try
        {
            using (IDbConnection connection = InspireDbConn)
            {
                connection.Open();
                var parameters = new DynamicParameters();
                parameters.Add("@UserID", mfaStatus.UserID);
                parameters.Add("@MFAStatus", mfaStatus.MFAStatus);
                parameters.Add("@Status", dbType: DbType.Int16, direction: ParameterDirection.Output, size: 1);
                parameters.Add("@ErrorMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 5000);

                connection.Query("SI_USR_UpdateMFAStatus", parameters, commandType: CommandType.StoredProcedure);

                result = new ResultModel<object>()
                {
                    Status = parameters.Get<Int16>("Status"),
                    Message = parameters.Get<string>("ErrorMessage"),
                    Data = null
                };
            }
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }

        return result;

    }
}

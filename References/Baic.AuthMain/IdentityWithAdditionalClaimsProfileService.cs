using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Baic.AuthMain.Models;
using Microsoft.AspNetCore.Identity;
using IdentityServer4;
using Baic.AuthMain.Services;

namespace Baic.AuthMain;

public class IdentityWithAdditionalClaimsProfileService : IProfileService
{
    private readonly IUserClaimsPrincipalFactory<IdentityUserExtended> _claimsFactory;
    private readonly UserManager<IdentityUserExtended> _userManager;
    private readonly IInspireUser _inspireUser;

    public IdentityWithAdditionalClaimsProfileService(UserManager<IdentityUserExtended> userManager, IUserClaimsPrincipalFactory<IdentityUserExtended> claimsFactory, IInspireUser inspireUser)
    {
        _userManager = userManager;
        _claimsFactory = claimsFactory;
        _inspireUser = inspireUser;
    }

    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        var sub = context.Subject.GetSubjectId();

        var user = await _userManager.FindByIdAsync(sub);
        var principal = await _claimsFactory.CreateAsync(user);

        var claims = principal.Claims.ToList();

        claims = claims.Where(claim => context.RequestedClaimTypes.Contains(claim.Type)).ToList();
        claims.Add(new Claim(JwtClaimTypes.GivenName, user.UserName));  

        if (user.TwoFactorEnabled)
        {
            claims.Add(new Claim("amr", "mfa"));
        }
        else
        {
            claims.Add(new Claim("amr", "pwd")); ;
        }

        claims.Add(new Claim(IdentityServerConstants.StandardScopes.Email, user.Email));

        var inspireUser = await _inspireUser.GetApplicationUserAsync(user.UserName);

        var defaultParams = new DefaultParameters()
        {
            UserID = inspireUser.UserId,
            UserPK = inspireUser.UserPk,
            UserType = inspireUser.UserType,
            Language = inspireUser.Language,
            UEditVersion = inspireUser.EditVersion,
            ComponentID = null
        };       

        claims.Add(new Claim("user_pk", inspireUser.UserPk.ToString()));
        claims.Add(new Claim("user_id", inspireUser.UserName));
        claims.Add(new Claim("user_type", inspireUser.UserType));
        claims.Add(new Claim("user_email", inspireUser.Email != null ? inspireUser.Email : "Not Available"));        
        claims.Add(new Claim("user_lang", inspireUser.Language));
        claims.Add(new Claim("user_edit_version", inspireUser.EditVersion.ToString()));  
        claims.Add(new Claim("auth_type", inspireUser.AuthType));
        claims.Add(new Claim("diary_display_days", inspireUser.DiaryDisplayDays.ToString()));
        claims.Add(new Claim("is_bank_icon", inspireUser.IsBankIcon.ToString()));
        claims.Add(new Claim("is_helpdesk", inspireUser.IsHelpDesk.ToString()));
        claims.Add(new Claim("is_underwriter", inspireUser.IsUnderwriter.ToString()));
        claims.Add(new Claim("is_inspector", inspireUser.IsInspection.ToString()));
        claims.Add(new Claim("user_name", inspireUser.FirstName + " " + inspireUser.LastName));
        claims.Add(new Claim("user_page", inspireUser.AnchorPage));
        claims.Add(new Claim("user_client_pk", inspireUser.UserClientPk.ToString()));
        






        var roles = await _inspireUser.GetAdditionalUserClaimsAsync(user.UserId, defaultParams);
        if(roles.Data.Count > 0)
        {
            foreach (var item in roles.Data)
            {
                claims.Add(new Claim("role", item.Name));
            }
        }   

        context.IssuedClaims = claims;
    }

    public async Task IsActiveAsync(IsActiveContext context)
    {
        var sub = context.Subject.GetSubjectId();
        var user = await _userManager.FindByIdAsync(sub);
        context.IsActive = user != null;
    }
}
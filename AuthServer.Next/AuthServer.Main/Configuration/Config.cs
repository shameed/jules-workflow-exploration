using OpenIddict.Abstractions;

namespace AuthServer.Main.Configuration;

public static class Config
{
    public static List<OpenIddictApplicationDescriptor> GetClients(IConfiguration configuration)
    {
        var stsConfig = configuration.GetSection("StsConfig");

        var clientUrl = stsConfig["ClientUrl"] ?? "http://localhost:4200";
        var clientName = stsConfig["ClientName"] ?? "Inspire Client";
        var clientId = stsConfig["ClientId"] ?? "InspireClient";

        var redirectUris = stsConfig["RedirectUris"] ?? "http://localhost:4200/auth-callback";
        var postLogoutRedirectUris = stsConfig["PostLogoutRedirectUris"] ?? "http://localhost:4200/";
        // var allowedOrigins = stsConfig["AllowedOrigins"] ?? "http://localhost:4200"; // OpenIddict usually handles this via CORS policy, not client config directly in the descriptor in the same way, but we can set RedirectURIs which validation uses.

        var redirectUriList = redirectUris.Split(',').Select(u => u.Trim()).Select(u => new Uri(u)).ToHashSet();
        var postLogoutRedirectUriList = postLogoutRedirectUris.Split(',').Select(u => u.Trim()).Select(u => new Uri(u)).ToHashSet();

        return new List<OpenIddictApplicationDescriptor>
        {
            new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                DisplayName = clientName,
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,

                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.GrantTypes.Password, // Added for legacy password grant support as requested

                    OpenIddictConstants.Permissions.ResponseTypes.Code,

                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles,
                    "openid",
                    "offline_access",
                    "InspireCommonApi",
                    "InspireClientApi"
                },
                RedirectUris = { }, // Populated below
                PostLogoutRedirectUris = { }, // Populated below
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                }
            }
        };
    }

    public static List<OpenIddictScopeDescriptor> GetScopes()
    {
        return new List<OpenIddictScopeDescriptor>
        {
            new OpenIddictScopeDescriptor
            {
                Name = "InspireCommonApi",
                DisplayName = "Scope for the InspireCommon ApiResource"
            },
            new OpenIddictScopeDescriptor
            {
                Name = "InspireClientApi",
                DisplayName = "Scope for the InspireClient ApiResource"
            }
        };
    }
}

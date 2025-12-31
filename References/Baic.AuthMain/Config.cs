// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityServer4.Models;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Linq;
using static System.Net.WebRequestMethods;

namespace Baic.AuthMain;

public class Config
{
    public static IEnumerable<IdentityResource> GetIdentityResources()
    {
        return new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email()
        };
    }

    public static IEnumerable<ApiScope> GetApiScopes()
    {
        return new List<ApiScope>
        {
            new ApiScope("InspireCommonApi", "Scope for the InspireCommon ApiResource"),
            new ApiScope("InspireClientApi",  "Scope for the InspireClient ApiResource")
        };
    }

    public static IEnumerable<ApiResource> GetApiResources()
    {
        return new List<ApiResource>
        {
            new ApiResource("InspireCommonApi")
            {
                ApiSecrets =
                {
                    new Secret("InspireCommonSecret".Sha256())
                },
                Scopes = new List<string> { "InspireCommonApi" }
            },
            new ApiResource("InspireClientApi")
            {
                ApiSecrets =
                {
                    new Secret("InspireClientSecret".Sha256())
                },
                Scopes = new List<string> { "InspireClientApi" }
            }
        };
    }

    public static IEnumerable<Client> GetClients(IConfigurationSection stsConfig)
    {
        var clientUrl = stsConfig["ClientUrl"];
        var clientName = stsConfig["ClientName"];
        var clientId = stsConfig["ClientId"];

        string redirectUris = stsConfig["RedirectUris"];
        string allowedOrigins = stsConfig["AllowedOrigins"];
        string postLogoutRedirectUris = stsConfig["PostLogoutRedirectUris"];


        List<string> redirectUrisList = new List<string>();
        redirectUrisList = redirectUris.Split(",").Select(v => v.Trim()).ToList();
        List<string> postLogoutRedirectUrisList = new List<string>();
        postLogoutRedirectUrisList = postLogoutRedirectUris.Split(",").Select(v => v.Trim()).ToList();
        List<string> allowedCorsOriginsList = new List<string>();
        allowedCorsOriginsList = allowedOrigins.Split(",").Select(v => v.Trim()).ToList();

        return new List<Client>
        {

            new Client
            {
                ClientName = clientName,
                ClientId = clientId,
                AccessTokenType = AccessTokenType.Jwt,
                AccessTokenLifetime = 1200, // 330 seconds, default 60 minutes
                IdentityTokenLifetime = 300,
                RefreshTokenExpiration = TokenExpiration.Absolute,
                AbsoluteRefreshTokenLifetime = 360000,
                SlidingRefreshTokenLifetime = 2592000 * 2,
                RefreshTokenUsage = TokenUsage.ReUse,
                //AllowedGrantTypes = GrantTypes.Code,
                AllowedGrantTypes = { "authorization_code", "refresh_token" },
                AllowAccessTokensViaBrowser = true,
                AllowOfflineAccess= true,
                RequireClientSecret= false,
                RedirectUris = redirectUrisList,
                PostLogoutRedirectUris = postLogoutRedirectUrisList,
                AllowedCorsOrigins = allowedCorsOriginsList,
                AllowedScopes = new List<string>
                {
                    "openid",
                    "profile",
                    "email",
                    "offline_access",
                    "InspireCommonApi",
                    "InspireClientApi"
                }
            }
        };
    }
}
using System.Data;
using AuthServer.Migration.SourceData;
using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AuthServer.Migration;

public class MigrationService
{
    private readonly LegacyDbContext _legacyDbContext;
    private readonly OldIdentityDbContext _oldIdentityDbContext;
    private readonly IConfiguration _configuration;
    private readonly ILogger<MigrationService> _logger;

    public MigrationService(
        LegacyDbContext legacyDbContext,
        OldIdentityDbContext oldIdentityDbContext,
        IConfiguration configuration,
        ILogger<MigrationService> logger)
    {
        _legacyDbContext = legacyDbContext;
        _oldIdentityDbContext = oldIdentityDbContext;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task RunAsync()
    {
        _logger.LogInformation("Starting migration...");

        var legacyUsers = await _legacyDbContext.Users.ToListAsync();
        _logger.LogInformation("Found {Count} users in LegacyDb.", legacyUsers.Count);

        var oldTokens = await _oldIdentityDbContext.UserTokens.ToDictionaryAsync(t => t.UserId);

        using var connection = new SqlConnection(_configuration.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        using var transaction = connection.BeginTransaction();

        try
        {
            foreach (var user in legacyUsers)
            {
                var newUserId = Guid.NewGuid().ToString();
                var now = DateTime.UtcNow;

                // Insert into AspNetUsers
                // Note: Assuming standard Identity columns. Setting PasswordHash to dummy.
                // Setting MustChangePassword (custom column) to 1 (true).
                var sqlUser = @"
                    INSERT INTO AspNetUsers (
                        Id, UserName, NormalizedUserName, Email, NormalizedEmail,
                        EmailConfirmed, PasswordHash, SecurityStamp, ConcurrencyStamp,
                        PhoneNumberConfirmed, TwoFactorEnabled, LockoutEnabled, AccessFailedCount,
                        MustChangePassword, ProfileData
                    ) VALUES (
                        @Id, @UserName, @NormalizedUserName, @Email, @NormalizedEmail,
                        @EmailConfirmed, @PasswordHash, @SecurityStamp, @ConcurrencyStamp,
                        @PhoneNumberConfirmed, @TwoFactorEnabled, @LockoutEnabled, @AccessFailedCount,
                        @MustChangePassword, @ProfileData
                    )";

                await connection.ExecuteAsync(sqlUser, new
                {
                    Id = newUserId,
                    UserName = user.Username,
                    NormalizedUserName = user.Username.ToUpperInvariant(),
                    Email = user.Email,
                    NormalizedEmail = user.Email.ToUpperInvariant(),
                    EmailConfirmed = true, // Assuming migrated users are verified
                    PasswordHash = "LEGACY_MIGRATED",
                    SecurityStamp = Guid.NewGuid().ToString(),
                    ConcurrencyStamp = Guid.NewGuid().ToString(),
                    PhoneNumberConfirmed = false,
                    TwoFactorEnabled = false, // Will enable if TOTP found
                    LockoutEnabled = true,
                    AccessFailedCount = 0,
                    MustChangePassword = true,
                    ProfileData = user.ProfileData
                }, transaction);

                // Check for TOTP
                if (oldTokens.TryGetValue(user.UserId, out var token) && !string.IsNullOrEmpty(token.TotpSecret))
                {
                    // Update TwoFactorEnabled
                    await connection.ExecuteAsync(
                        "UPDATE AspNetUsers SET TwoFactorEnabled = 1 WHERE Id = @Id",
                        new { Id = newUserId }, transaction);

                    // Insert TOTP secret into AspNetUserTokens
                    // Provider: Authenticator (Standard ASP.NET Identity provider name)
                    // Name: AuthenticatorKey
                    var sqlToken = @"
                        INSERT INTO AspNetUserTokens (UserId, LoginProvider, Name, Value)
                        VALUES (@UserId, 'Authenticator', 'AuthenticatorKey', @Value)";

                    await connection.ExecuteAsync(sqlToken, new
                    {
                        UserId = newUserId,
                        Value = token.TotpSecret
                    }, transaction);
                }
            }

            transaction.Commit();
            _logger.LogInformation("Migration completed successfully.");
        }
        catch (Exception ex)
        {
            transaction.Rollback();
            _logger.LogError(ex, "Migration failed.");
            throw;
        }
    }
}

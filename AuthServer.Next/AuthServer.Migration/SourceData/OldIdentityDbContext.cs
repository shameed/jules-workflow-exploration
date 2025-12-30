using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Migration.SourceData;

public class OldUserToken
{
    [Key]
    public int Id { get; set; }
    public int UserId { get; set; }
    public string? TotpSecret { get; set; }
}

public class OldIdentityDbContext : DbContext
{
    public OldIdentityDbContext(DbContextOptions<OldIdentityDbContext> options) : base(options) { }
    public DbSet<OldUserToken> UserTokens { get; set; }
}

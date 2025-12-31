using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Baic.AuthMain.Models;

namespace Baic.AuthMain.Data;

public class ApplicationDbContext : IdentityDbContext<IdentityUserExtended>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<FidoStoredCredential> FidoStoredCredential { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.Entity<FidoStoredCredential>().HasKey(m => m.Id);

        base.OnModelCreating(builder);
    }
}
using AuthServer.Migration;
using AuthServer.Migration.SourceData;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddDbContext<LegacyDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("LegacyConnection")));

builder.Services.AddDbContext<OldIdentityDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("OldIdentityConnection")));

builder.Services.AddTransient<MigrationService>();

var host = builder.Build();

var migrationService = host.Services.GetRequiredService<MigrationService>();
await migrationService.RunAsync();

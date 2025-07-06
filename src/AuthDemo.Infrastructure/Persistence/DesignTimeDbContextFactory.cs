using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace AuthDemo.Infrastructure.Persistence;

public sealed class DesignTimeDbContextFactory
    : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    public ApplicationDbContext CreateDbContext(string[] args)
    {
        // ① 接続文字列を直接書くか、環境変数 / user-secrets から読む
        var conn = Environment.GetEnvironmentVariable("POSTGRES_CONN")
                   ?? "Host=localhost;Port=5432;Database=authdemo;Username=postgres;Password=postgres";

        var opts = new DbContextOptionsBuilder<ApplicationDbContext>()
                   .UseNpgsql(conn, o => o.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName))
                   .EnableSensitiveDataLogging()     // ← 好みで
                   .Options;

        return new ApplicationDbContext(opts);
    }
}

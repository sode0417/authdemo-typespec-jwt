using AuthDemo.Infrastructure.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthDemo.Infrastructure.Persistence;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : DbContext(options)
{
    public DbSet<User> Users => Set<User>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // User テーブル構成
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(u => u.Id);

            entity.Property(u => u.Email)
                  .IsRequired()
                  .HasMaxLength(255);

            entity.HasIndex(u => u.Email)
                  .IsUnique();

            // ソフトデリート用フィルター (Phase 2 で IsDeleted に切り替え)
            entity.HasQueryFilter(u => !u.IsDeleted);
        });
    }
}

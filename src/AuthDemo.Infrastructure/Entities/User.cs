namespace AuthDemo.Infrastructure.Entities;

public class User
{
    public Guid     Id           { get; set; } = Guid.NewGuid();  // 主キー
    public string   Email        { get; set; } = default!;        // 要 null 許容でない文字列
    public string   PasswordHash { get; set; } = default!;
    public DateTime CreatedAt    { get; set; } = DateTime.UtcNow;
    public bool     IsDeleted    { get; set; } = false;           // Soft-Delete 用
}

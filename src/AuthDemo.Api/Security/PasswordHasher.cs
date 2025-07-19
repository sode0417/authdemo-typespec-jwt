using BCrypt.Net;

namespace AuthDemo.Api.Security;

public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hash);
}

public class PasswordHasher : IPasswordHasher
{
    private const int WorkFactor = 12;  // BCryptのワークファクター（計算コスト）

    public string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
    }

    public bool VerifyPassword(string password, string hash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        catch (Exception)
        {
            // ハッシュが無効な場合などの例外は検証失敗として扱う
            return false;
        }
    }
}
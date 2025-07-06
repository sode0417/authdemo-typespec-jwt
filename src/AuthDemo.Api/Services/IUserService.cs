using AuthDemo.Infrastructure.Entities;

namespace AuthDemo.Api.Services;

public record SignUpResult(string Id, string Username);
public record SignInResult(string Token, string Username);

public interface IUserService
{
    /// <summary>
    /// ユーザーを新規登録します
    /// </summary>
    Task<SignUpResult> SignUpAsync(string username, string password);

    /// <summary>
    /// ユーザーを認証し、JWTトークンを発行します
    /// </summary>
    Task<SignInResult> SignInAsync(string username, string password);

    /// <summary>
    /// ユーザー名が既に使用されているかを確認します
    /// </summary>
    Task<bool> IsUsernameExistsAsync(string username);
}
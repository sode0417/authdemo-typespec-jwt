using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthDemo.Api.Options;
using AuthDemo.Api.Security;
using AuthDemo.Infrastructure.Entities;
using AuthDemo.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthDemo.Api.Services;

public class UserService : IUserService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IPasswordHasher _passwordHasher;
    private readonly JwtOptions _jwtOptions;

    public UserService(
        ApplicationDbContext dbContext,
        IPasswordHasher passwordHasher,
        IOptions<JwtOptions> jwtOptions)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
        _jwtOptions = jwtOptions.Value;
    }

    public async Task<SignUpResult> SignUpAsync(string username, string password)
    {
        // ユーザー名の重複チェック
        if (await IsUsernameExistsAsync(username))
        {
            throw new InvalidOperationException("Username already exists");
        }

        // パスワードのハッシュ化とユーザー作成
        var user = new User
        {
            Email = username,
            PasswordHash = _passwordHasher.HashPassword(password)
        };

        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        return new SignUpResult(user.Id.ToString(), user.Email);
    }

    public async Task<SignInResult> SignInAsync(string username, string password)
    {
        // ユーザーの検索
        var user = await _dbContext.Users
            .FirstOrDefaultAsync(u => u.Email == username && !u.IsDeleted);

        if (user == null)
        {
            throw new InvalidOperationException("Invalid username or password");
        }

        // パスワードの検証
        if (!_passwordHasher.VerifyPassword(password, user.PasswordHash))
        {
            throw new InvalidOperationException("Invalid username or password");
        }

        // JWTトークンの生成
        var token = GenerateJwtToken(user);

        return new SignInResult(token, user.Email);
    }

    public async Task<bool> IsUsernameExistsAsync(string username)
    {
        return await _dbContext.Users
            .AnyAsync(u => u.Email == username && !u.IsDeleted);
    }

    private string GenerateJwtToken(User user)
    {
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(
                _jwtOptions.Key ?? Environment.GetEnvironmentVariable("JWT_KEY")
                ?? throw new InvalidOperationException("Signing key is missing")));
        var credentials = new SigningCredentials(
            key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        var token = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
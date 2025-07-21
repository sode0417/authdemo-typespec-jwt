using System.Text;
using AuthDemo.Api.Options;
using AuthDemo.Api.Common;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace AuthDemo.Api.Extensions;

public static class JwtAuthenticationExtensions
{
    public static IServiceCollection AddJwtAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // JwtOptionsをDIコンテナに登録
        services.Configure<JwtOptions>(
            configuration.GetSection(JwtOptions.SectionName));

        var jwtOptions = configuration
            .GetSection(JwtOptions.SectionName)
            .Get<JwtOptions>();

        if (jwtOptions == null)
        {
            throw new InvalidOperationException("JwtOptions configuration is missing");
        }

        var key = TestJwtConstants.Key; // Force test-specific key
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new InvalidOperationException("JWT key is not configured");
        }
        jwtOptions.Key = key;
        if (string.IsNullOrWhiteSpace(jwtOptions.Key))
        {
            throw new InvalidOperationException("JWT key is not configured");
        }

        // JWT Bearer認証を追加
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ValidateIssuerSigningKey = true,
                    RequireSignedTokens = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidIssuer = "AuthDemo", // Match test-specific issuer
                    ValidAudience = "AuthDemo", // Match test-specific audience
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(TestJwtConstants.Key)) // Force test-specific key
                };

                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = ctx =>
                    {
                        ctx.NoResult();
                        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        return Task.CompletedTask;
                    },
                    OnChallenge = ctx =>
                    {
                        ctx.HandleResponse();
                        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        return Task.CompletedTask;
                    }
                };
                // Enhanced debug logs for validation parameters
                Console.WriteLine($"[DEBUG] ValidIssuer: {jwtOptions.Issuer}");
                Console.WriteLine($"[DEBUG] ValidAudience: {jwtOptions.Audience}");
                Console.WriteLine($"[DEBUG] IssuerSigningKey: {jwtOptions.Key}");
                Console.WriteLine($"[DEBUG] Environment JWT_KEY: {Environment.GetEnvironmentVariable("JWT_KEY")}");
                Console.WriteLine($"[DEBUG] Configuration Jwt:Key: {configuration["Jwt:Key"]}");
                Console.WriteLine($"Environment JWT_KEY: {Environment.GetEnvironmentVariable("JWT_KEY")}");
                Console.WriteLine($"Configuration Jwt:Key: {configuration["Jwt:Key"]}");
            });

        return services;
    }
}
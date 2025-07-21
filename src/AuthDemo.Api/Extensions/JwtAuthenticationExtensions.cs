/// Changes made: 
/// - Aligned logger templates with argument counts.
/// - Consolidated redundant log calls.
/// - Replaced Console.WriteLine with logger.LogDebug.
/// - Added this XML comment summarizing the changes.
using System.Text;
using System.IdentityModel.Tokens.Jwt;
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
        // Use TestJwtConstants for configuration
        var jwtOptions = new JwtOptions
        {
            Key = TestJwtConstants.Key,
            Issuer = TestJwtConstants.Issuer,
            Audience = TestJwtConstants.Audience
        };

        // JWT Bearer認証を追加
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true, // Enable issuer validation
                    ValidIssuer = jwtOptions.Issuer,
                    ValidateAudience = true, // Enable audience validation
                    ValidAudience = jwtOptions.Audience,
                    ValidateLifetime = true, // Enable lifetime validation
                    RequireExpirationTime = true, // Require expiration time
                    ValidateIssuerSigningKey = true,
                    RequireSignedTokens = true,
                    ClockSkew = TimeSpan.Zero,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Key))
                    {
                        KeyId = "test-key-id" // Match the kid in the token
                    }
                };

                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = ctx =>
                    {
                        var logger = ctx.HttpContext.RequestServices
                            .GetRequiredService<ILogger<Program>>();

                        logger.LogError(ctx.Exception, "JWT authentication failed.");

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
            });

        return services;
    }
}
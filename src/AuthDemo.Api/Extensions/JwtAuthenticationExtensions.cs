using System.Text;
using AuthDemo.Api.Options;
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

        // JWT Bearer認証を追加
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtOptions.Issuer,
                    ValidAudience = jwtOptions.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(jwtOptions.Key)),
                    ClockSkew = TimeSpan.Zero
                };
            });

        return services;
    }
}
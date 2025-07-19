using AuthDemo.Api.Security;
using AuthDemo.Api.Services;
using AuthDemo.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace AuthDemo.Api.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // DbContext を登録
        services.AddDbContextPool<ApplicationDbContext>(opts =>
            opts.UseNpgsql(configuration.GetConnectionString("Default")));

        // JWT認証と認可を追加
        services.AddJwtAuthentication(configuration);
        services.AddAuthorization();

        // API関連の設定を追加
        services.AddControllers()
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
            });

        // 認証関連のサービスを登録
        services.AddScoped<IPasswordHasher, PasswordHasher>();
        services.AddScoped<IUserService, UserService>();

        // Swagger/OpenAPI の設定
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "AuthDemo API",
                Version = "v1",
                Description = "認証デモアプリケーションのAPI"
            });

            // JWT認証の設定
            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "JWTトークンを入力してください: Bearer {token}"
            });

            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    Array.Empty<string>()
                }
            });

            options.EnableAnnotations();
        });

        return services;
    }
}
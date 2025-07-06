using AuthDemo.Api.Extensions;
using AuthDemo.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// DbContext を登録
builder.Services.AddDbContextPool<ApplicationDbContext>(opts =>
    opts.UseNpgsql(builder.Configuration.GetConnectionString("Default")));

// JWT認証と認可を追加
builder.Services.AddJwtAuthentication(builder.Configuration);
builder.Services.AddAuthorization();

var app = builder.Build();

// 認証・認可ミドルウェアを有効化
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello AuthDemo!");

// サンプルの保護エンドポイント
app.MapGet("/profile", () => Results.Ok(new { message = "This is a protected endpoint" }))
    .RequireAuthorization();

app.Run();

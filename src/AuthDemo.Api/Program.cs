using AuthDemo.Api.Extensions;
using AuthDemo.Api.Security;
using AuthDemo.Api.Services;
using AuthDemo.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// DbContext を登録
builder.Services.AddDbContextPool<ApplicationDbContext>(opts =>
    opts.UseNpgsql(builder.Configuration.GetConnectionString("Default")));

// JWT認証と認可を追加
builder.Services.AddJwtAuthentication(builder.Configuration);
builder.Services.AddAuthorization();

// 認証関連のサービスを登録
builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();
builder.Services.AddScoped<IUserService, UserService>();

var app = builder.Build();

// 認証・認可ミドルウェアを有効化
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello AuthDemo!");

// サンプルの保護エンドポイント
app.MapGet("/profile", () => Results.Ok(new { message = "This is a protected endpoint" }))
    .RequireAuthorization();

// 認証エンドポイント
app.MapPost("/auth/signup", async (SignUpRequest request, IUserService userService) =>
{
    try
    {
        var result = await userService.SignUpAsync(request.username, request.password);
        return Results.Ok(new SignUpResponse { id = result.Id, username = result.Username });
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/auth/signin", async (SignInRequest request, IUserService userService) =>
{
    try
    {
        var result = await userService.SignInAsync(request.username, request.password);
        return Results.Ok(new SignInResponse { token = result.Token, username = result.Username });
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// リクエスト・レスポンスの型定義
record SignUpRequest(string username, string password);
record SignUpResponse
{
    public string id { get; init; } = default!;
    public string username { get; init; } = default!;
}

record SignInRequest(string username, string password);
record SignInResponse
{
    public string token { get; init; } = default!;
    public string username { get; init; } = default!;
}

app.Run();

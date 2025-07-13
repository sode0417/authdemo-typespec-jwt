using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using AuthDemo.Api;
using AuthDemo.Infrastructure.Persistence;

namespace AuthDemo.Api.Tests.Security;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration(config =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] = "DataSource=:memory:",
                ["Jwt:Issuer"] = "AuthDemo",
                ["Jwt:Audience"] = "AuthDemo"
            });
        });

        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            if (descriptor != null)
            {
                services.Remove(descriptor);
            }

            services.AddDbContextPool<ApplicationDbContext>(opts =>
                opts.UseInMemoryDatabase("TestDb"));

            Environment.SetEnvironmentVariable("JWT_KEY", "TestSecretKey_for_unit_tests_1234567890");
        });
    }
}

public static class JwtTokenHelper
{
    public static string CreateToken(
        string? issuer = "AuthDemo",
        string? audience = "AuthDemo",
        DateTime? expires = null,
        string? key = "TestSecretKey_for_unit_tests_1234567890")
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = expires ?? DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = credentials
        });
        return handler.WriteToken(token);
    }
}

public class JwtAuthenticationTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly HttpClient _client;

    public JwtAuthenticationTests(CustomWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task ProtectedEndpoint_WithoutToken_Returns401()
    {
        var res = await _client.GetAsync("/profile");
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithInvalidSignature_Returns401()
    {
        var token = JwtTokenHelper.CreateToken(key: "other-secret-key");
        var request = new HttpRequestMessage(HttpMethod.Get, "/profile");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var res = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithExpiredToken_Returns401()
    {
        var token = JwtTokenHelper.CreateToken(expires: DateTime.UtcNow.AddMinutes(-5));
        var request = new HttpRequestMessage(HttpMethod.Get, "/profile");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var res = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithWrongIssuer_Returns401()
    {
        var token = JwtTokenHelper.CreateToken(issuer: "OtherIssuer");
        var request = new HttpRequestMessage(HttpMethod.Get, "/profile");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var res = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithWrongAudience_Returns401()
    {
        var token = JwtTokenHelper.CreateToken(audience: "OtherAudience");
        var request = new HttpRequestMessage(HttpMethod.Get, "/profile");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var res = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }
}

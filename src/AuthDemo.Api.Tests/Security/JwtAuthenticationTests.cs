using AuthDemo.Api.Tests.Common;
#nullable enable
using System;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using AuthDemo.Api.Tests.Helpers;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using AuthDemo.Api;
using AuthDemo.Infrastructure.Persistence;
using Xunit;

using System.Collections.Generic;
using System.Linq;

namespace AuthDemo.Api.Tests.Security;

/// <summary>
/// Custom factory for configuring the web application during JWT authentication tests.
/// </summary>
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

            Environment.SetEnvironmentVariable("JWT_KEY", TestJwtConstants.Key);
        });
    }
}

/// <summary>
/// Provides helper methods for creating JWT tokens during tests.
/// </summary>
public static class JwtTokenHelper
{
    /// <summary>
    /// Creates a JWT token with the specified parameters for testing purposes.
    /// </summary>
    /// <param name="issuer">The issuer of the token.</param>
    /// <param name="audience">The audience of the token.</param>
    /// <param name="notBefore">The start time of the token validity.</param>
    /// <param name="expires">The expiration time of the token.</param>
    /// <param name="key">The secret key used for signing the token.</param>
    /// <returns>A signed JWT token as a string.</returns>
    public static string CreateToken(
        string? issuer = "AuthDemo",
        string? audience = "AuthDemo",
        DateTime? notBefore = null,
        DateTime? expires = null,
        string? key = "TestSecretKey_for_unit_tests_12345678901234567890123456789012") // 32文字以上
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            NotBefore = notBefore ?? DateTime.UtcNow,
            Expires = expires ?? DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = credentials
        });
        return handler.WriteToken(token);
    }
}

/// <summary>
/// Contains test cases for verifying JWT authentication functionality.
/// </summary>
public class JwtAuthenticationTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly HttpClient _client;

    public JwtAuthenticationTests(CustomWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    /// <summary>
    /// Tests that accessing a protected endpoint without a token returns a 401 Unauthorized status.
    /// </summary>
    public async Task ProtectedEndpoint_WithoutToken_Returns401()
    {
        var res = await _client.GetAsync("/profile");
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    public static IEnumerable<object[]> InvalidTokenCases =>
        new[]
        {
            new object[] { "invalid-signature", TestJwtConstants.Issuer, TestJwtConstants.Audience, "ValidKey_12345678901234567890123456789012", null, null },
            new object[] { "expired", TestJwtConstants.Issuer, TestJwtConstants.Audience, TestJwtConstants.Key, DateTime.UtcNow.AddMinutes(-10), DateTime.UtcNow.AddMinutes(-5) },
            new object[] { "wrong-issuer", "OtherIssuer", TestJwtConstants.Audience, TestJwtConstants.Key, null, null },
            new object[] { "wrong-audience", TestJwtConstants.Issuer, "OtherAudience", TestJwtConstants.Key, null, null },
        };

    [Theory(DisplayName = "Invalid tokens return 401")]
    [MemberData(nameof(InvalidTokenCases))]
    public async Task Invalid_Tokens_Return401(
string issuer, string audience, string key,
        DateTime? nbf, DateTime? exp)
    {
        var token = JwtTokenHelper.CreateToken(issuer, audience, nbf, exp, key);
        var res = await HttpClientExtensions.GetProfileAsync(_client, token);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }
    [Fact]
    /// <summary>
    /// Tests that accessing a protected endpoint with a valid token returns a 200 OK status.
    /// </summary>
    public async Task ProtectedEndpoint_WithValidToken_Returns200()
    {
        var token = JwtTokenHelper.CreateToken(
        issuer: TestJwtConstants.Issuer,
        audience: TestJwtConstants.Audience,
        key: TestJwtConstants.Key);
        var response = await HttpClientExtensions.GetProfileAsync(_client, token);
        var res = response;
        Console.WriteLine($"[DEBUG] Generated Token: {token}");
        Console.WriteLine($"[DEBUG] Response Status Code: {res.StatusCode}");
        Console.WriteLine($"[DEBUG] Response Content: {await res.Content.ReadAsStringAsync()}");
        // Log expected validation parameters for debugging
        // Additional debug log for token validation
        // Log response details for debugging
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }
}

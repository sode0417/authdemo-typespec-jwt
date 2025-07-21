using AuthDemo.Api.Common;
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
    string caseDescription, string issuer, string audience, string key,
            DateTime? nbf, DateTime? exp)
    {
        Console.WriteLine($"[DEBUG] Test Case: {caseDescription}");
        Console.WriteLine($"[DEBUG] Issuer: {issuer}, Audience: {audience}, Key: {key}, NotBefore: {nbf}, Expiration: {exp}");
        var token = JwtTokenHelper.CreateToken(issuer, audience, nbf, exp, key);
        Console.WriteLine($"[DEBUG] Generated Token: {token}");
        var res = await HttpClientExtensions.GetProfileAsync(_client, token);
        Console.WriteLine($"[DEBUG] Response Status Code: {res.StatusCode}");
        Console.WriteLine($"[DEBUG] Response Content: {await res.Content.ReadAsStringAsync()}");
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
        Console.WriteLine($"[DEBUG] Token Validation Parameters: Issuer={TestJwtConstants.Issuer}, Audience={TestJwtConstants.Audience}, Key={TestJwtConstants.Key}");
        Console.WriteLine($"[DEBUG] Token Header Algorithm: {SecurityAlgorithms.HmacSha256}");
        Console.WriteLine($"[DEBUG] Token Header Key ID: test-key-id");
        var response = await HttpClientExtensions.GetProfileAsync(_client, token);
        var res = response;
        Console.WriteLine($"[DEBUG] Generated Token: {token}");
        Console.WriteLine($"[DEBUG] Response Status Code: {res.StatusCode}");
        Console.WriteLine($"[DEBUG] Response Content: {await res.Content.ReadAsStringAsync()}");
        Console.WriteLine($"[DEBUG] Expected Status Code: 200 OK");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }
}

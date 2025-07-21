#nullable enable

using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.Testing;
using AuthDemo.Api.Tests.Common;
using AuthDemo.Api.Options;

namespace AuthDemo.Api.Tests.Security;

/// <summary>
/// Custom factory for configuring the web application during tests.
/// </summary>
public class CustomWebApplicationFactory<TStartup> : WebApplicationFactory<TStartup> where TStartup : class
{
    /// <summary>
    /// Configures the web host for testing purposes.
    /// </summary>
    /// <param name="builder">The web host builder to configure.</param>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        Environment.SetEnvironmentVariable("JWT_KEY", TestJwtConstants.Key);

        builder.ConfigureAppConfiguration((context, configBuilder) =>
        {
            configBuilder.AddInMemoryCollection(new[]
        {
        new KeyValuePair<string, string>("Jwt:Key", "TestSecretKey_for_unit_tests_1234567890"), // Force consistent key
        new KeyValuePair<string, string>("Jwt:Issuer", "AuthDemo"), // Ensure consistent Issuer
        new KeyValuePair<string, string>("Jwt:Audience", "AuthDemo") // Ensure consistent Audience
          });
        });

        builder.ConfigureServices((context, services) =>
        {
            services.Configure<JwtOptions>(options =>
        {
              options.Key = TestJwtConstants.Key;
              options.Issuer = TestJwtConstants.Issuer;
              options.Audience = TestJwtConstants.Audience;
          });
        });

        builder.ConfigureServices(services =>
        {
            // Additional service configuration if needed
        });
    }
}
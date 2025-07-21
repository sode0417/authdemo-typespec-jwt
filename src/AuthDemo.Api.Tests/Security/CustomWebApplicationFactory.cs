#nullable enable

using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.Testing;
using AuthDemo.Api.Common;
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
        Environment.SetEnvironmentVariable("JWT_ISSUER", TestJwtConstants.Issuer);
        Environment.SetEnvironmentVariable("JWT_AUDIENCE", TestJwtConstants.Audience);

        builder.ConfigureAppConfiguration((context, configBuilder) =>
        {
            /// Updated to use KeyValuePair.Create for cleaner syntax and null-safe values.
            configBuilder.AddInMemoryCollection(new[]
            {
                new KeyValuePair<string, string?>("Jwt:Key", TestJwtConstants.Key),
                new KeyValuePair<string, string?>("Jwt:Issuer", TestJwtConstants.Issuer),
                new KeyValuePair<string, string?>("Jwt:Audience", TestJwtConstants.Audience)
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

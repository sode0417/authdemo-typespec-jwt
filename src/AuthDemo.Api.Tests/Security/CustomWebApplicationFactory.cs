using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.Testing;
using AuthDemo.Api.Tests.Common;

namespace AuthDemo.Api.Tests.Security
{
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
      /// <summary>
      /// Sets the environment to "Testing" to avoid dev-only JWT settings.
      /// </summary>
      builder.UseEnvironment("Testing");

      Environment.SetEnvironmentVariable("JWT_KEY", TestJwtConstants.Key);

      builder.ConfigureAppConfiguration((context, configBuilder) =>
      {
        configBuilder.AddInMemoryCollection(new[]
              {
                    new KeyValuePair<string, string>("Jwt:Key", TestJwtConstants.Key)
          });
      });

      builder.ConfigureServices(services =>
      {
        // Additional service configuration if needed
      });
    }
  }
}
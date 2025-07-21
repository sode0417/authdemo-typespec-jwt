using AuthDemo.Api.Extensions;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddApplicationServices(builder.Configuration);

var keyFromConfig = builder.Configuration["Jwt:Key"];
var keyFromEnv = Environment.GetEnvironmentVariable("JWT_KEY");
var signingKey = keyFromConfig ?? keyFromEnv;

if (string.IsNullOrWhiteSpace(signingKey))
  throw new InvalidOperationException(
      "Signing key is missing. Set Jwt:Key in configuration or JWT_KEY environment variable.");

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

var app = builder.Build();
app.UseAuthentication(); // Activate authentication middleware
app.UseAuthorization(); // Activate authorization middleware
app.ConfigureEndpoints();
app.Run();

public partial class Program { }

using AuthDemo.Api.Extensions;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddApplicationServices(builder.Configuration);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

var app = builder.Build();
app.UseAuthentication(); // Activate authentication middleware
app.UseAuthorization(); // Activate authorization middleware
app.ConfigureEndpoints();
app.Run();

public partial class Program { }

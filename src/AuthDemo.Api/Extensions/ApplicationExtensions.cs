using AuthDemo.Api.Models;
using AuthDemo.Api.Services;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace AuthDemo.Api.Extensions;

public static class ApplicationExtensions
{
    public static WebApplication ConfigureEndpoints(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();

        MapEndpoints(app);

        return app;
    }

    private static void MapEndpoints(WebApplication app)
    {
        app.MapGet("/", () => "Hello AuthDemo!")
            .WithMetadata(new SwaggerOperationAttribute("Get Home", "Returns a welcome message"));

        app.MapGet("/profile", () => 
            Results.Ok(new { message = "This is a protected endpoint" }))
            .RequireAuthorization()
            .WithMetadata(new SwaggerOperationAttribute("Get Profile", "Returns protected profile information"));

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
        })
        .WithName("SignUp")
        .WithMetadata(new SwaggerOperationAttribute("Sign Up", "Register a new user"));

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
        })
        .WithName("SignIn")
        .WithMetadata(new SwaggerOperationAttribute("Sign In", "Authenticate and get JWT token"));
    }
}
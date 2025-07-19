namespace AuthDemo.Api.Models;

public record SignUpRequest(string username, string password);

public record SignUpResponse
{
    public string id { get; init; } = default!;
    public string username { get; init; } = default!;
}

public record SignInRequest(string username, string password);

public record SignInResponse
{
    public string token { get; init; } = default!;
    public string username { get; init; } = default!;
}
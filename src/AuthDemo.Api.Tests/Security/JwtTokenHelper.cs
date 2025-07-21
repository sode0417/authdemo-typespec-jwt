#nullable enable

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthDemo.Api.Tests.Security;

/// <summary>
/// Provides utility methods for creating JWT tokens.
/// </summary>
public static class JwtTokenUtility
{
    /// <summary>
    /// Creates a JWT token with the specified parameters.
    /// </summary>
    /// <param name="key">The secret key used for signing the token.</param>
    /// <param name="issuer">The issuer of the token.</param>
    /// <param name="audience">The audience of the token.</param>
    /// <returns>A signed JWT token as a string.</returns>
    public static string CreateToken(
        string key,
        string issuer,
        string audience)
    {
        Console.WriteLine($"Creating token with Issuer: {issuer}, Audience: {audience}, Key: {key}");

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claimsIdentity = new ClaimsIdentity(new[]
        {
            new Claim("sub", "test")
        });
        Console.WriteLine($"Adding claim: sub=test");

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = credentials,
            Subject = claimsIdentity
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        Console.WriteLine("Token creation process completed.");

        return tokenHandler.WriteToken(token);
    }
}
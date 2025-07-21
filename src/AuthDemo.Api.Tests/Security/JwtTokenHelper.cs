#nullable enable

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthDemo.Api.Tests.Security;

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
        var keyBytes = Encoding.UTF8.GetBytes(key!);
        Console.WriteLine($"[DEBUG] Raw Signing Key Bytes: {BitConverter.ToString(keyBytes)}");
        Console.WriteLine($"[DEBUG] Token Generation Algorithm: {SecurityAlgorithms.HmacSha256}");

        var securityKey = new SymmetricSecurityKey(keyBytes);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        // Create the token header manually to include the kid
        var header = new JwtHeader(credentials)
        {
            { "kid", "test-key-id" }
        };

        // Create the token payload
        var payload = new JwtPayload(
            issuer: issuer,
            audience: audience,
            claims: null,
            notBefore: notBefore ?? DateTime.UtcNow,
            expires: expires ?? DateTime.UtcNow.AddMinutes(30)
        );

        // Create the token
        var token = new JwtSecurityToken(header, payload);

        var handler = new JwtSecurityTokenHandler();
        var tokenString = handler.WriteToken(token);

        // Decode and log the token header for debugging
        var parts = tokenString.Split('.');
        if (parts.Length == 3)
        {
            string DecodeBase64Url(string input)
            {
                string base64 = input.Replace('-', '+').Replace('_', '/');
                switch (base64.Length % 4)
                {
                    case 2: base64 += "=="; break;
                    case 3: base64 += "="; break;
                }
                return Encoding.UTF8.GetString(Convert.FromBase64String(base64));
            }

            var decodedHeader = DecodeBase64Url(parts[0]);
            Console.WriteLine($"[DEBUG] Decoded Token Header: {decodedHeader}");

            // Compute the signature for comparison
            using var hmac = new HMACSHA256(keyBytes);
            var expectedSignatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]));
            var expectedSignature = Convert.ToBase64String(expectedSignatureBytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
            Console.WriteLine($"[DEBUG] Expected Signature: {expectedSignature}");

            // Manual validation logic for debugging
            if (parts.Length == 3)
            {
                var actualSignature = parts[2];
                Console.WriteLine($"[DEBUG] Actual Signature: {actualSignature}");
                if (expectedSignature == actualSignature)
                {
                    Console.WriteLine("[DEBUG] Signature validation succeeded.");
                }
                else
                {
                    Console.WriteLine("[DEBUG] Signature validation failed.");
                }
            }
            else
            {
                Console.WriteLine("[DEBUG] Token structure is invalid.");
            }
        }
        else
        {
            Console.WriteLine("[DEBUG] Token structure is invalid.");
        }

        return tokenString;
    }
}
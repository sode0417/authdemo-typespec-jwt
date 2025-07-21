#nullable enable

namespace AuthDemo.Api.Common;

/// <summary>JWT 設定値をテスト全体で共有する。</summary>
public static class TestJwtConstants
{
    public const string Issuer = "AuthDemo";
    public const string Audience = "AuthDemo";
    public const string Key = "TestSecretKey_for_unit_tests_12345678901234567890";
}
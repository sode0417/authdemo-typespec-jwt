#nullable enable
namespace AuthDemo.Api.Common;

/// <summary>
/// JWT 設定値をテスト・本番共通で保持する。
/// </summary>
public static class TestJwtConstants
{
    public const string Issuer = "AuthDemo";
    public const string Audience = "AuthDemo";
    // 32 byte (以上) のキーを必ず維持
    public const string Key = "TestSecretKey_for_unit_tests_12345678901234567890";
}
namespace AuthDemo.Api.Tests.Common
{
  /// <summary>
  /// <summary>
  /// Provides constants for JWT testing purposes.
  /// </summary>
  /// </summary>
  internal static class TestJwtConstants
  {
    /// <summary>
    /// Secret key used for JWT token generation in tests.
    /// </summary>
    public const string Key = "TestSecretKey_for_unit_tests_1234567890";
    /// <summary>
    /// Issuer used for JWT token generation in tests.
    /// </summary>
    public const string Issuer = "AuthDemo";
    /// <summary>
    /// Audience used for JWT token generation in tests.
    /// </summary>
    public const string Audience = "AuthDemo";
  }
}
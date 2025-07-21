#nullable enable

using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace AuthDemo.Api.Tests.Helpers;

internal static class HttpClientExtensions
{
    /// <summary>Bearer トークン付き GET /profile を発行。</summary>
    internal static Task<HttpResponseMessage> GetProfileAsync(
        this HttpClient client, string token)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/profile");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client.SendAsync(req);
    }
}
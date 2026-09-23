using System.Net.Http;

namespace TrustBeat.Tests;

internal static class TrustBeatClientTestFactory
{
    /// <summary>
    /// A client over a stubbed handler. 429 retries never really wait: each wait is recorded
    /// in <paramref name="waits"/> when given, and otherwise skipped.
    /// </summary>
    internal static TrustBeatClient Create(
        Func<HttpRequestMessage, HttpResponseMessage> handler,
        int maxRetries = 2,
        List<TimeSpan>? waits = null)
        => new("tb_live_test", "http://localhost/v1", new StubMessageHandler(handler))
        {
            MaxRetries = maxRetries,
            RetryDelay = (d, _) => { waits?.Add(d); return Task.CompletedTask; },
        };

    private sealed class StubMessageHandler(
        Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage req, CancellationToken ct)
            => Task.FromResult(handler(req));
    }
}

using System.Net.Http;

namespace TrustBeat.Tests;

internal static class TrustBeatClientTestFactory
{
    internal static TrustBeatClient Create(
        Func<HttpRequestMessage, HttpResponseMessage> handler)
        => new("tb_live_test", "http://localhost/v1", new StubMessageHandler(handler));

    private sealed class StubMessageHandler(
        Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage req, CancellationToken ct)
            => Task.FromResult(handler(req));
    }
}

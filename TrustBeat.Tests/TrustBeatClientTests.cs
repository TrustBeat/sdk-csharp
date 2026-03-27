using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace TrustBeat.Tests;

/// <summary>
/// Unit tests for TrustBeatClient HTTP methods.
/// Uses a custom HttpMessageHandler to stub network calls — no real server needed.
/// </summary>
public class TrustBeatClientTests
{
    // ── Stub infrastructure ───────────────────────────────────────────────────

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage req, CancellationToken ct)
            => Task.FromResult(handler(req));
    }

    private static TrustBeatClient ClientWith(
        Func<HttpRequestMessage, HttpResponseMessage> handler)
    {
        // We need to inject a custom handler — reach into ApiClient via reflection
        // or use a test-friendly factory. We expose a constructor for tests.
        return TrustBeatClientTestFactory.Create(handler);
    }

    private static HttpResponseMessage Ok(string json)
        => new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Status(HttpStatusCode code, string json)
        => new(code) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static string AnchorAccepted(string id = "track-1") =>
        $$"""{"id":"{{id}}","hash":"{{"a".PadRight(64, 'a')}}","hash_algorithm":"sha256","status":"pending","submitted_at":"2026-01-01T00:00:00Z","overage":false}""";

    private static string ProofJson(string id = "track-1")
    {
        var leaf  = new string('a', 64);
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes("DER_BYTES"));
        return $$"""{"id":"{{id}}","hash":"{{leaf}}","hash_algorithm":"sha256","batch_id":"batch-1","leaf_index":0,"merkle_root":"{{leaf}}","proof_path":[],"token":"{{token}}","token_format":"rfc3161","tsa_serial":"42","provider":"sk-demo","anchored_at":"2026-01-01T00:10:00Z","client_ref":null,"description":null}""";
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    private static byte[] H(string s)   => SHA256.HashData(Encoding.UTF8.GetBytes(s));

    // ── anchor() ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task AnchorReturnsAnchorJob()
    {
        var client = ClientWith(_ => Ok(AnchorAccepted()));
        var job    = await client.AnchorAsync("a".PadRight(64, 'a'));
        Assert.Equal("track-1", job.Id);
        Assert.Equal("pending",  job.Status);
        Assert.False(job.Overage);
    }

    [Fact]
    public async Task AnchorSendsBearerToken()
    {
        string? authHeader = null;
        var client = ClientWith(req =>
        {
            authHeader = req.Headers.Authorization?.ToString();
            return Ok(AnchorAccepted());
        });
        await client.AnchorAsync("a".PadRight(64, 'a'));
        Assert.Equal("Bearer tb_live_test", authHeader);
    }

    [Fact]
    public async Task AnchorSendsClientRef()
    {
        string? body = null;
        var client = ClientWith(req =>
        {
            body = req.Content!.ReadAsStringAsync().Result;
            return Ok(AnchorAccepted());
        });
        await client.AnchorAsync("b".PadRight(64, 'b'), new AnchorOptions { ClientRef = "ref-1" });
        Assert.Contains("\"client_ref\":\"ref-1\"", body);
    }

    [Fact]
    public async Task AnchorSendsPostToAnchorsEndpoint()
    {
        string? method = null; string? path = null;
        var client = ClientWith(req =>
        {
            method = req.Method.Method;
            path   = req.RequestUri?.PathAndQuery;
            return Ok(AnchorAccepted());
        });
        await client.AnchorAsync("a".PadRight(64, 'a'));
        Assert.Equal("POST",     method);
        Assert.Equal("/v1/anchors", path);
    }

    // ── anchorBatch() ─────────────────────────────────────────────────────────

    [Fact]
    public async Task AnchorBatchReturnsListOfJobs()
    {
        var client = ClientWith(_ => Ok(
            $$"""{"accepted":[{{AnchorAccepted("t1")}},{{AnchorAccepted("t2")}}],"total":2}"""));
        var jobs = await client.AnchorBatchAsync(["a".PadRight(64, 'a'), "b".PadRight(64, 'b')]);
        Assert.Equal(2, jobs.Count);
        Assert.Equal("t1", jobs[0].Id);
        Assert.Equal("t2", jobs[1].Id);
    }

    [Fact]
    public async Task AnchorBatchEmptyReturnsEmptyWithoutRequest()
    {
        bool called = false;
        var client  = ClientWith(_ => { called = true; return Ok("{}"); });
        var result  = await client.AnchorBatchAsync([]);
        Assert.Empty(result);
        Assert.False(called);
    }

    [Fact]
    public async Task AnchorBatchOver100Throws()
    {
        var client = ClientWith(_ => Ok("{}"));
        var hashes = Enumerable.Repeat("a".PadRight(64, 'a'), 101).ToList();
        await Assert.ThrowsAsync<ArgumentException>(() => client.AnchorBatchAsync(hashes));
    }

    // ── getProof() ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetProofReturnsProofWhenAnchored()
    {
        var client = ClientWith(_ => Ok(ProofJson()));
        var proof  = await client.GetProofAsync("track-1");
        Assert.NotNull(proof);
        Assert.Equal("DER_BYTES", Encoding.UTF8.GetString(proof.Token));
        Assert.Equal("42", proof.TsaSerial);
    }

    [Fact]
    public async Task GetProofReturnsNullWhenPending()
    {
        var client = ClientWith(_ => Ok(AnchorAccepted()));
        Assert.Null(await client.GetProofAsync("track-1"));
    }

    // ── anchorWait() ──────────────────────────────────────────────────────────

    [Fact]
    public async Task AnchorWaitPollsUntilProofReady()
    {
        int calls = 0;
        var client = ClientWith(_ => Ok(++calls == 1 ? AnchorAccepted() : ProofJson()));
        var proof  = await client.AnchorWaitAsync("track-1",
            new AnchorWaitOptions { TimeoutSecs = 30, PollIntervalSecs = 0 });
        Assert.NotNull(proof);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task AnchorWaitThrowsTimeoutException()
    {
        var client = ClientWith(_ => Ok(AnchorAccepted()));
        await Assert.ThrowsAsync<TimeoutException>(() =>
            client.AnchorWaitAsync("track-1",
                new AnchorWaitOptions { TimeoutSecs = 0, PollIntervalSecs = 0 }));
    }

    // ── verify() ─────────────────────────────────────────────────────────────

    [Fact]
    public void VerifyReturnsTrueForValidSingleLeafProof()
    {
        var leaf  = Hex(H("content"));
        var proof = new AnchorProof("x", leaf, "sha256", "b", 0, leaf,
                                    [], [], "rfc3161", "0", "test",
                                    "2026-01-01T00:00:00Z", null, null);
        Assert.True(new TrustBeatClient("tb_live_test").Verify(proof));
    }

    [Fact]
    public void VerifyReturnsFalseForInvalidProof()
    {
        var leaf  = Hex(H("content"));
        var proof = new AnchorProof("x", leaf, "sha256", "b", 0, new string('f', 64),
                                    [], [], "rfc3161", "0", "test",
                                    "2026-01-01T00:00:00Z", null, null);
        Assert.False(new TrustBeatClient("tb_live_test").Verify(proof));
    }

    // ── Error mapping ─────────────────────────────────────────────────────────

    [Theory]
    [InlineData(401, typeof(AuthException))]
    [InlineData(402, typeof(QuotaException))]
    [InlineData(404, typeof(NotFoundException))]
    [InlineData(429, typeof(RateLimitException))]
    public async Task HttpErrorsMappedToCorrectExceptions(int statusCode, Type exType)
    {
        var client = ClientWith(_ => Status(
            (HttpStatusCode)statusCode,
            """{"error":{"message":"test error"}}"""));
        var ex = await Assert.ThrowsAnyAsync<TrustBeatException>(
            () => client.AnchorAsync("a".PadRight(64, 'a')));
        Assert.IsType(exType, ex);
        Assert.Equal(statusCode, ex.Status);
    }

    [Fact]
    public async Task Http500TrustBeatExceptionWithStatus()
    {
        var client = ClientWith(_ => Status(HttpStatusCode.InternalServerError,
            """{"error":{"message":"Server error"}}"""));
        var ex = await Assert.ThrowsAsync<TrustBeatException>(
            () => client.AnchorAsync("a".PadRight(64, 'a')));
        Assert.Equal(500, ex.Status);
    }

    // ── Constructor validation ────────────────────────────────────────────────

    [Fact]
    public void EmptyApiKeyThrows()
        => Assert.Throws<ArgumentException>(() => new TrustBeatClient(""));

    [Fact]
    public void NullApiKeyThrows()
        => Assert.Throws<ArgumentException>(() => new TrustBeatClient(null!));

    // ── Static hash utilities ─────────────────────────────────────────────────

    [Fact]
    public void HashBytesReturns64CharLowercaseHex()
    {
        var h = TrustBeatClient.HashBytes("hello"u8.ToArray());
        Assert.Equal(64, h.Length);
        Assert.Matches("^[0-9a-f]+$", h);
    }

    [Fact]
    public void HashStringMatchesHashBytes()
    {
        Assert.Equal(TrustBeatClient.HashBytes("world"u8.ToArray()),
                     TrustBeatClient.HashString("world"));
    }

    [Fact]
    public async Task HashStreamMatchesHashBytes()
    {
        var data   = "stream content"u8.ToArray();
        var stream = new MemoryStream(data);
        Assert.Equal(TrustBeatClient.HashBytes(data),
                     await TrustBeatClient.HashStreamAsync(stream));
    }

    // ── AnchorFileAsync() ─────────────────────────────────────────────────────

    [Fact]
    public async Task HashFileAsyncMatchesHashBytes()
    {
        var content = "deterministic content 42"u8.ToArray();
        var path    = Path.GetTempFileName();
        try
        {
            await System.IO.File.WriteAllBytesAsync(path, content);
            var expected = TrustBeatClient.HashBytes(content);
            Assert.Equal(expected, await TrustBeatClient.HashFileAsync(path));
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public async Task AnchorFileAsyncSendsCorrectHash()
    {
        var content  = "hello trustbeat"u8.ToArray();
        var expected = TrustBeatClient.HashBytes(content);
        string? capturedHash = null;

        var client = ClientWith(req =>
        {
            var body = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            var doc  = System.Text.Json.JsonDocument.Parse(body);
            capturedHash = doc.RootElement.GetProperty("hash").GetString();
            return Ok(AnchorAccepted("track-f1"));
        });

        var path = Path.GetTempFileName();
        try
        {
            await System.IO.File.WriteAllBytesAsync(path, content);
            var job = await client.AnchorFileAsync(path);
            Assert.Equal("track-f1", job.Id);
            Assert.Equal(expected, capturedHash);
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public async Task AnchorFileAsyncDescriptionDefaultsToFilename()
    {
        string? capturedDesc = null;

        var client = ClientWith(req =>
        {
            var body = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            var doc  = System.Text.Json.JsonDocument.Parse(body);
            doc.RootElement.TryGetProperty("description", out var p);
            capturedDesc = p.GetString();
            return Ok(AnchorAccepted());
        });

        var path = Path.GetTempFileName();
        try
        {
            await System.IO.File.WriteAllBytesAsync(path, "data"u8.ToArray());
            await client.AnchorFileAsync(path);
            Assert.Equal(Path.GetFileName(path), capturedDesc);
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public async Task AnchorFileAsyncCustomDescriptionOverridesFilename()
    {
        string? capturedDesc = null;

        var client = ClientWith(req =>
        {
            var body = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            var doc  = System.Text.Json.JsonDocument.Parse(body);
            doc.RootElement.TryGetProperty("description", out var p);
            capturedDesc = p.GetString();
            return Ok(AnchorAccepted());
        });

        var path = Path.GetTempFileName();
        try
        {
            await System.IO.File.WriteAllBytesAsync(path, "data"u8.ToArray());
            await client.AnchorFileAsync(path, new AnchorOptions { Description = "my-doc" });
            Assert.Equal("my-doc", capturedDesc);
        }
        finally { System.IO.File.Delete(path); }
    }
}

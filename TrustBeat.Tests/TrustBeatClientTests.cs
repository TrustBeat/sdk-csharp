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
    public async Task AnchorSendsPostToAnchorEndpoint()
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
        Assert.Equal("/v1/anchor", path);
    }

    // ── anchorBatch() ─────────────────────────────────────────────────────────

    [Fact]
    public async Task AnchorBatchReturnsBatchSubmission()
    {
        var client = ClientWith(_ => Ok(
            $$"""{"submission_id":"sub-abc","accepted":[{{AnchorAccepted("t1")}},{{AnchorAccepted("t2")}}],"total":2}"""));
        var result = await client.AnchorBatchAsync(["a".PadRight(64, 'a'), "b".PadRight(64, 'b')]);
        Assert.Equal("sub-abc", result.SubmissionId);
        Assert.Equal(2, result.Items.Count);
        Assert.Equal("t1", result.Items[0].Id);
        Assert.Equal("t2", result.Items[1].Id);
    }

    [Fact]
    public async Task AnchorBatchEmptyReturnsEmptyWithoutRequest()
    {
        bool called = false;
        var client  = ClientWith(_ => { called = true; return Ok("{}"); });
        var result  = await client.AnchorBatchAsync([]);
        Assert.Empty(result.Items);
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

    // ── getAiDecisionProof() pending ────────────────────────────────────────────

    [Fact]
    public async Task GetAiDecisionProofReturnsNullWhilePending()
    {
        // Before anchoring the API returns 200 with verification_status "PENDING".
        var client = ClientWith(_ => Ok(
            """{"id":"ai-1","input_hash":"","output_hash":"","combined_hash":"","metadata":{},"verification_status":"PENDING","anchored_at":null,"proof":null}"""));
        var proof = await client.GetAiDecisionProofAsync("ai-1");
        Assert.Null(proof);
    }

    // ── exportAuditEvents() requires from/to ────────────────────────────────────

    [Fact]
    public async Task ExportAuditEventsRequiresFromAndTo()
    {
        bool called = false;
        var client = ClientWith(_ => { called = true; return Ok("{}"); });
        await Assert.ThrowsAsync<ArgumentException>(
            () => client.ExportAuditEventsAsync("", "2026-04-16T00:00:00Z"));
        await Assert.ThrowsAsync<ArgumentException>(
            () => client.ExportAuditEventsAsync("2026-04-15T00:00:00Z", ""));
        Assert.False(called);
    }

    [Fact]
    public async Task SubmitAuditEventsSendsBareArray()
    {
        string? body = null;
        var client = ClientWith(req =>
        {
            body = req.Content!.ReadAsStringAsync().Result;
            return Ok("""{"event_ids":["e1","e2"]}""");
        });
        var events = new IReadOnlyDictionary<string, object?>[]
        {
            new Dictionary<string, object?> { ["trail_category"] = "financial", ["actor"] = "svc:pay", ["action"] = "payment.approved", ["ts"] = "2026-04-15T10:00:00Z" },
            new Dictionary<string, object?> { ["trail_category"] = "financial", ["actor"] = "svc:pay", ["action"] = "payment.settled",  ["ts"] = "2026-04-15T10:00:05Z" },
        };
        var ids = await client.SubmitAuditEventsAsync(events);
        Assert.Equal(new[] { "e1", "e2" }, ids);
        Assert.StartsWith("[", body!.TrimStart());
        Assert.Contains("payment.approved", body);
    }

    // ── Tamper-Evident Logs (NIS2) ──────────────────────────────────────────────

    private static string LogProofJson(string status)
    {
        var proof = status == "VERIFIED" ? ProofJson("log-1") : "null";
        var anchored = status == "PENDING" ? "null" : "\"2026-04-15T10:10:00Z\"";
        var a64 = new string('a', 64);
        var c64 = new string('c', 64);
        return $$$"""{"id":"log-1","log_hash":"{{{a64}}}","combined_hash":"{{{c64}}}","metadata":{"log_source":{"uri":"/var/log/app.log","name":"App","size_bytes":2048},"source_identity":{"hostname":"host-1","service_name":"payments"},"time_envelope":{"start_at":"2026-04-15T00:00:00Z","end_at":"2026-04-15T23:59:59Z"}},"verification_status":"{{{status}}}","archive_stamps_count":0,"anchored_at":{{{anchored}}},"proof":{{{proof}}}}""";
    }

    [Fact]
    public async Task AnchorLogSendsBodyAndParses()
    {
        string? body = null;
        var client = ClientWith(req =>
        {
            body = req.Content!.ReadAsStringAsync().Result;
            return Ok($$"""{"id":"log-1","log_hash":"{{new string('b', 64)}}","combined_hash":"{{new string('c', 64)}}","status":"pending","submitted_at":"2026-04-15T10:00:00Z","overage":false,"label":"lbl"}""");
        });
        var meta = new LogMetadata(
            new LogSource("/var/log/app.log", "App", 2048),
            new LogSourceIdentity(Hostname: "host-1", ServiceName: "payments"),
            new LogTimeEnvelope("2026-04-15T00:00:00Z", "2026-04-15T23:59:59Z"));
        var job = await client.AnchorLogAsync(new string('b', 64), meta, "lbl");
        Assert.Equal("log-1", job.Id);
        Assert.Equal("lbl", job.Label);
        Assert.Contains("\"log_hash\":\"" + new string('b', 64) + "\"", body);
        Assert.Contains("\"uri\":\"/var/log/app.log\"", body);
        Assert.Contains("\"service_name\":\"payments\"", body);
        Assert.Contains("\"size_bytes\":2048", body);
        Assert.Contains("\"end_at\":\"2026-04-15T23:59:59Z\"", body);
    }

    [Fact]
    public async Task GetLogProofReturnsProofWhenVerified()
    {
        var client = ClientWith(_ => Ok(LogProofJson("VERIFIED")));
        var p = await client.GetLogProofAsync("log-1");
        Assert.NotNull(p);
        Assert.Equal("VERIFIED", p!.VerificationStatus);
        Assert.Equal("/var/log/app.log", p.Metadata.LogSource.Uri);
        Assert.NotNull(p.Proof);
    }

    [Fact]
    public async Task GetLogProofReturnsNullWhenPending()
    {
        var client = ClientWith(_ => Ok(LogProofJson("PENDING")));
        Assert.Null(await client.GetLogProofAsync("log-1"));
    }

    [Fact]
    public async Task GetLogStatusAndListLogs()
    {
        var s = ClientWith(_ => Ok("""{"id":"log-1","status":"anchored","submitted_at":"2026-04-15T10:00:00Z","anchored_at":"2026-04-15T10:10:00Z"}"""));
        var st = await s.GetLogStatusAsync("log-1");
        Assert.Equal("anchored", st.Status);
        Assert.Equal("2026-04-15T10:10:00Z", st.AnchoredAt);

        string? path = null;
        var l = ClientWith(req =>
        {
            path = req.RequestUri!.PathAndQuery;
            return Ok($$"""{"logs":[{"id":"log-1","log_hash":"{{new string('a', 64)}}","status":"anchored","submitted_at":"2026-04-15T10:00:00Z","log_source_uri":"/var/log/app.log","service_name":"payments","label":"x"}],"total":1}""");
        });
        var logs = await l.ListLogsAsync(status: "anchored");
        Assert.Single(logs);
        Assert.Equal("/var/log/app.log", logs[0].LogSourceUri);
        Assert.Contains("status=anchored", path);
    }

    [Fact]
    public async Task ExportLogReturnsBytes()
    {
        var client = ClientWith(_ => Ok("""{"bundle_type":"trustbeat.log.proof","id":"log-1"}"""));
        var blob = await client.ExportLogAsync("log-1");
        Assert.Contains("trustbeat.log.proof", System.Text.Encoding.UTF8.GetString(blob));
    }

    [Fact]
    public async Task ExportAiDecisionReturnsBytes()
    {
        string? requestedPath = null;
        var client = ClientWith(req =>
        {
            requestedPath = req.RequestUri!.AbsolutePath;
            return Ok("""{"bundle_type":"trustbeat.ai.proof","id":"dec-1"}""");
        });
        var blob = await client.ExportAiDecisionAsync("dec-1");
        Assert.Contains("trustbeat.ai.proof", System.Text.Encoding.UTF8.GetString(blob));
        Assert.EndsWith("/v1/ai/decisions/dec-1/export", requestedPath);
    }

    [Fact]
    public async Task ExportAiDecisionNotFound()
    {
        var client = ClientWith(_ => Status(
            HttpStatusCode.NotFound,
            """{"error":{"message":"Unknown ID","code":"NOT_FOUND"}}"""));
        await Assert.ThrowsAsync<NotFoundException>(() => client.ExportAiDecisionAsync("nope"));
    }

    [Fact]
    public async Task ExportVerificationReturnsBytes()
    {
        string? requestedPath = null;
        var client = ClientWith(req =>
        {
            requestedPath = req.RequestUri!.AbsolutePath;
            return Ok("""{"bundle_type":"trustbeat.verification.proof","id":"ver-1"}""");
        });
        var blob = await client.ExportVerificationAsync("ver-1");
        Assert.Contains("trustbeat.verification.proof", System.Text.Encoding.UTF8.GetString(blob));
        Assert.EndsWith("/v1/verify/ver-1/export", requestedPath);
    }
}

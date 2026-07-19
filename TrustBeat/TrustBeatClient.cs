using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using TrustBeat.Internal;

namespace TrustBeat;

/// <summary>
/// TrustBeat SDK client.
///
/// <code>
/// var client = new TrustBeatClient("tb_live_...");
/// var job    = await client.AnchorAsync("abc...64hex");
/// var proof  = await client.AnchorWaitAsync(job.Id);
/// bool valid = client.Verify(proof);
/// </code>
///
/// Zero runtime dependencies — uses System.Net.Http and System.Security.Cryptography.
/// Thread-safe; share a single instance across the application.
/// </summary>
public sealed class TrustBeatClient : IDisposable
{
    internal const string DefaultBaseUrl = "https://api.trustbeat.eu/v1";

    private readonly ApiClient _api;

    /// <param name="apiKey">Your TrustBeat API key (tb_live_... or tb_test_...).</param>
    /// <param name="baseUrl">Override the API base URL. Defaults to https://api.trustbeat.eu/v1.</param>
    /// <param name="timeout">HTTP request timeout. Defaults to 30 seconds.</param>
    public TrustBeatClient(
        string  apiKey,
        string  baseUrl = DefaultBaseUrl,
        TimeSpan? timeout = null)
    {
        if (string.IsNullOrEmpty(apiKey))
            throw new ArgumentException("apiKey must not be empty", nameof(apiKey));

        _api = new ApiClient(apiKey, baseUrl, timeout ?? TimeSpan.FromSeconds(30));
    }

    /// <summary>Test-only constructor — injects a stub HttpMessageHandler.</summary>
    internal TrustBeatClient(string apiKey, string baseUrl,
                             System.Net.Http.HttpMessageHandler handler)
    {
        if (string.IsNullOrEmpty(apiKey))
            throw new ArgumentException("apiKey must not be empty", nameof(apiKey));
        _api = new ApiClient(apiKey, baseUrl, handler);
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>Submit a SHA-256 hash for Merkle anchoring.</summary>
    public async Task<AnchorJob> AnchorAsync(string hash,
        AnchorOptions? options = null, CancellationToken ct = default)
    {
        var body = Json.BuildObject(
            ("hash",           hash),
            ("hash_algorithm", "SHA-256"),
            ("client_ref",     options?.ClientRef),
            ("description",    options?.Description));

        var data = await _api.PostAsync("/anchor", body, ct).ConfigureAwait(false);
        return ApiClient.ParseAnchorJob(data);
    }

    /// <summary>
    /// Submit up to 100 SHA-256 hashes in a single batch.
    /// Returns a <see cref="BatchSubmission"/> grouping all items under one SubmissionId.
    /// Use <see cref="AnchorBatchWaitAsync"/> to block until all proofs are ready.
    /// </summary>
    public async Task<BatchSubmission> AnchorBatchAsync(
        IReadOnlyList<string> hashes,
        AnchorOptions? options = null,
        CancellationToken ct = default)
    {
        if (hashes.Count == 0) return new BatchSubmission("", []);
        if (hashes.Count > 100)
            throw new ArgumentException("AnchorBatch: maximum 100 hashes per request");

        var items = "[" + string.Join(",",
            hashes.Select(h => Json.BuildObject(("hash", h), ("hash_algorithm", "SHA-256")))) + "]";

        var body = Json.BuildObject(
            ("hashes",      new Json.RawJson(items)),
            ("client_ref",  options?.ClientRef),
            ("description", options?.Description));

        var data = await _api.PostAsync("/anchor/batch", body, ct).ConfigureAwait(false);
        var submissionId = Json.Str(data, "submission_id") ?? "";
        var jobs = Json.Array(data, "accepted").Select(ApiClient.ParseAnchorJob).ToList();
        return new BatchSubmission(submissionId, jobs);
    }

    /// <summary>Return anchored/pending counts for a batch submission.</summary>
    public async Task<BatchStatus> GetBatchStatusAsync(
        string submissionId, CancellationToken ct = default)
    {
        var path = "/anchor/batch/" + Uri.EscapeDataString(submissionId) + "/status";
        var data = await _api.GetAsync(path, ct).ConfigureAwait(false);
        return new BatchStatus(
            SubmissionId: Json.Str(data, "submission_id") ?? submissionId,
            Total:        Json.Int(data, "total"),
            Anchored:     Json.Int(data, "anchored"),
            Pending:      Json.Int(data, "pending")
        );
    }

    /// <summary>Return all anchored inclusion proofs for a batch submission.</summary>
    public async Task<IReadOnlyList<AnchorProof>> GetBatchProofsAsync(
        string submissionId, CancellationToken ct = default)
    {
        var path = "/anchor/batch/" + Uri.EscapeDataString(submissionId) + "/proofs";
        var data = await _api.GetAsync(path, ct).ConfigureAwait(false);
        return Json.Array(data, "proofs").Select(ApiClient.ParseProof).ToList();
    }

    /// <summary>
    /// Poll until all hashes in a batch submission are anchored, then return all proofs.
    /// Throws <see cref="TimeoutException"/> if not complete within the timeout.
    /// </summary>
    public async Task<IReadOnlyList<AnchorProof>> AnchorBatchWaitAsync(
        BatchSubmission submission,
        AnchorWaitOptions? options = null,
        CancellationToken ct = default)
    {
        var opts     = options ?? new AnchorWaitOptions();
        var deadline = DateTime.UtcNow.AddSeconds(opts.TimeoutSecs);

        while (true)
        {
            var status = await GetBatchStatusAsync(submission.SubmissionId, ct).ConfigureAwait(false);
            if (status.Pending == 0 && status.Total > 0)
                return await GetBatchProofsAsync(submission.SubmissionId, ct).ConfigureAwait(false);

            if (DateTime.UtcNow >= deadline)
                throw new TimeoutException(
                    $"AnchorBatchWait timed out after {opts.TimeoutSecs}s for {submission.SubmissionId}");

            await Task.Delay(TimeSpan.FromSeconds(opts.PollIntervalSecs), ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Retrieve a proof by tracking ID.
    /// Returns <c>null</c> if the anchor is still pending.
    /// </summary>
    public async Task<AnchorProof?> GetProofAsync(string trackingId, CancellationToken ct = default)
    {
        var path = "/anchor/" + Uri.EscapeDataString(trackingId) + "/proof";
        var data = await _api.GetAsync(path, ct).ConfigureAwait(false);
        return ApiClient.LooksLikeProof(data) ? ApiClient.ParseProof(data) : null;
    }

    /// <summary>
    /// Poll until the proof is ready, then return it.
    /// Throws <see cref="TimeoutException"/> if no proof within <see cref="AnchorWaitOptions.TimeoutSecs"/>.
    /// </summary>
    public async Task<AnchorProof> AnchorWaitAsync(
        string trackingId,
        AnchorWaitOptions? options = null,
        CancellationToken ct = default)
    {
        var opts     = options ?? new AnchorWaitOptions();
        var deadline = DateTime.UtcNow.AddSeconds(opts.TimeoutSecs);

        while (true)
        {
            var proof = await GetProofAsync(trackingId, ct).ConfigureAwait(false);
            if (proof is not null) return proof;

            if (DateTime.UtcNow >= deadline)
                throw new TimeoutException(
                    $"AnchorWait timed out after {opts.TimeoutSecs}s for {trackingId}");

            await Task.Delay(TimeSpan.FromSeconds(opts.PollIntervalSecs), ct)
                      .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verify a Merkle inclusion proof locally — no network call.
    /// Returns <c>true</c> if the proof is cryptographically valid.
    /// Throws <see cref="VerificationException"/> if the proof data is malformed.
    /// </summary>
    public bool Verify(AnchorProof proof) => MerkleVerifier.Verify(proof);

    // ── Static hashing utilities ───────────────────────────────────────────────

    /// <summary>SHA-256 hash of a byte array, as a lowercase hex string.</summary>
    public static string HashBytes(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    /// <summary>SHA-256 hash of a UTF-8 string, as a lowercase hex string.</summary>
    public static string HashString(string text)
        => HashBytes(Encoding.UTF8.GetBytes(text));

    /// <summary>SHA-256 hash of a stream, as a lowercase hex string.</summary>
    public static async Task<string> HashStreamAsync(Stream stream, CancellationToken ct = default)
    {
        var digest = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    /// <summary>SHA-256 hash of a local file, as a lowercase hex string.</summary>
    public static async Task<string> HashFileAsync(string path, CancellationToken ct = default)
    {
        await using var stream = File.OpenRead(path);
        return await HashStreamAsync(stream, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Hash a local file with SHA-256 and submit it for anchoring.
    /// The file is never uploaded — only the 64-character hex digest is sent.
    /// <c>Description</c> defaults to the filename if not provided.
    /// </summary>
    public async Task<AnchorJob> AnchorFileAsync(
        string path,
        AnchorOptions? options = null,
        CancellationToken ct = default)
    {
        var hash = await HashFileAsync(path, ct).ConfigureAwait(false);
        var opts = options ?? new AnchorOptions();
        if (opts.Description is null)
            opts = new AnchorOptions { ClientRef = opts.ClientRef, Description = System.IO.Path.GetFileName(path) };
        return await AnchorAsync(hash, opts, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Hash a file, submit for anchoring, and wait for the proof.
    /// Convenience wrapper around <see cref="AnchorFileAsync"/> + <see cref="AnchorWaitAsync"/>.
    /// </summary>
    public async Task<AnchorProof> AnchorFileWaitAsync(
        string path,
        AnchorOptions? options = null,
        AnchorWaitOptions? waitOptions = null,
        CancellationToken ct = default)
    {
        var job = await AnchorFileAsync(path, options, ct).ConfigureAwait(false);
        return await AnchorWaitAsync(job.Id, waitOptions, ct).ConfigureAwait(false);
    }

    // ── AI Act Audit Anchoring ─────────────────────────────────────────────────

    /// <summary>
    /// Submit an AI decision for EU AI Act Article 12 anchoring.
    /// Privacy-safe: only hashes are sent — raw model inputs and outputs are never uploaded.
    /// Returns immediately with a tracking ID. Use <see cref="AnchorAiDecisionWaitAsync"/>
    /// to block until the proof is ready (~10 minutes).
    /// </summary>
    public async Task<AiDecisionJob> AnchorAiDecisionAsync(
        string             inputHash,
        string             outputHash,
        AiDecisionMetadata metadata,
        AiDecisionOptions? options = null,
        CancellationToken  ct = default)
    {
        var te = Json.BuildObject(
            ("started_at",   metadata.TimeEnvelope.StartedAt),
            ("completed_at", metadata.TimeEnvelope.CompletedAt));

        var meta = Json.BuildObject(
            ("model_id",              metadata.ModelId),
            ("model_version",         metadata.ModelVersion),
            ("system_name",           metadata.SystemName),
            ("risk_category",         metadata.RiskCategory),
            ("decision_type",         metadata.DecisionType),
            ("human_oversight",       metadata.HumanOversight.ToString().ToLower()),
            ("operator_id",           metadata.OperatorId),
            ("deployment_env",        metadata.DeploymentEnv),
            ("external_ref",          metadata.ExternalRef),
            ("decision_outcome",      metadata.DecisionOutcome),
            ("model_artifact_hash",   metadata.ModelArtifactHash),
            ("data_subject_category", metadata.DataSubjectCategory));
        // Inject time_envelope object and fix human_oversight (Json.BuildObject quotes booleans)
        meta = meta
            .Replace($"\"human_oversight\":\"{metadata.HumanOversight.ToString().ToLower()}\"",
                     $"\"human_oversight\":{metadata.HumanOversight.ToString().ToLower()}")
            .TrimEnd('}') + $",\"time_envelope\":{te}}}";

        var body = $"{{\"input_hash\":\"{inputHash}\",\"output_hash\":\"{outputHash}\",\"metadata\":{meta}}}";
        if (options?.CallbackUrl is not null)
            body = body.TrimEnd('}') + $",\"callback_url\":\"{options.CallbackUrl}\"}}";

        var data = await _api.PostAsync("/ai/decisions/anchor", body, ct).ConfigureAwait(false);
        return ApiClient.ParseAiDecisionJob(data);
    }

    /// <summary>
    /// Retrieve the verification result for a previously submitted AI decision.
    /// Returns <c>null</c> if the decision is still pending (not yet anchored).
    /// Throws <see cref="NotFoundException"/> if the tracking ID is unknown.
    /// </summary>
    public async Task<AiDecisionProof?> GetAiDecisionProofAsync(
        string trackingId, CancellationToken ct = default)
    {
        try
        {
            var data = await _api.GetAsync(
                $"/ai/decisions/verify/{Uri.EscapeDataString(trackingId)}", ct)
                .ConfigureAwait(false);
            // Before anchoring the API returns 200 with verification_status
            // "PENDING" and no proof — treat that as "not ready yet" so pollers
            // keep waiting.
            if (data.TryGetValue("verification_status", out var vs) && vs?.ToString() == "PENDING")
                return null;
            return ApiClient.ParseAiDecisionProof(data);
        }
        catch (NotFoundException e) when (e.Code == "NOT_ANCHORED")
        {
            return null;
        }
    }

    /// <summary>
    /// Poll until the AI decision proof is ready, then return it.
    /// Throws <see cref="TimeoutException"/> if not ready within the timeout.
    /// </summary>
    public async Task<AiDecisionProof> AnchorAiDecisionWaitAsync(
        string            trackingId,
        AnchorWaitOptions? options = null,
        CancellationToken  ct = default)
    {
        var opts     = options ?? new AnchorWaitOptions();
        var deadline = DateTime.UtcNow.AddSeconds(opts.TimeoutSecs);

        while (true)
        {
            var proof = await GetAiDecisionProofAsync(trackingId, ct).ConfigureAwait(false);
            if (proof is not null) return proof;

            if (DateTime.UtcNow >= deadline)
                throw new TimeoutException(
                    $"AnchorAiDecisionWait timed out after {opts.TimeoutSecs}s for {trackingId}");

            await Task.Delay(TimeSpan.FromSeconds(opts.PollIntervalSecs), ct)
                      .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Download a portable AI Act proof bundle (bundle_type "trustbeat.ai.proof").
    /// Returns the raw JSON bundle bytes. Throws <see cref="NotFoundException"/> if
    /// the ID is unknown or the decision is not yet anchored.
    /// </summary>
    public async Task<byte[]> ExportAiDecisionAsync(string trackingId, CancellationToken ct = default)
    {
        var (contentType, body) = await _api.GetRawAsync(
            $"/ai/decisions/{Uri.EscapeDataString(trackingId)}/export", ct).ConfigureAwait(false);
        ThrowIfErrorBundle(contentType, body, "AI decision export failed");
        return body;
    }

    // ── Signature & certificate verification ─────────────────────────────────

    /// <summary>
    /// Verify eIDAS electronic signatures on a document.
    /// Validates PAdES (PDF), CAdES (CMS), or XAdES (XML) against the EU Trusted List.
    /// </summary>
    /// <param name="document">Raw document bytes.</param>
    /// <param name="format">"pades", "cades", or "xades".</param>
    /// <param name="options">Optional verify options (callback URL, etc.).</param>
    public async Task<VerificationReport> VerifySignatureAsync(
        byte[]         document,
        string         format,
        VerifyOptions? options = null,
        CancellationToken ct  = default)
    {
        var body = Json.BuildObject(
            ("document_base64", Convert.ToBase64String(document)),
            ("format",          format),
            ("callback_url",    options?.CallbackUrl));
        var data = await _api.PostAsync("/verify/signature", body, ct).ConfigureAwait(false);
        return ApiClient.ParseVerificationReport(data);
    }

    /// <summary>
    /// Verify eIDAS signatures and anchor the verification event.
    /// Returns immediately (202) with a tracking ID.
    /// Use <see cref="GetVerificationAsync"/> to retrieve the completed report.
    /// </summary>
    public async Task<VerificationJob> VerifyAndAnchorAsync(
        byte[]         document,
        string         format,
        VerifyOptions? options = null,
        CancellationToken ct  = default)
    {
        var body = Json.BuildObject(
            ("document_base64", Convert.ToBase64String(document)),
            ("format",          format),
            ("callback_url",    options?.CallbackUrl));
        var data = await _api.PostAsync("/verify/signature/anchored", body, ct).ConfigureAwait(false);
        return ApiClient.ParseVerificationJob(data);
    }

    /// <summary>Retrieve a saved verification report by tracking ID.</summary>
    public async Task<VerificationReport> GetVerificationAsync(
        string trackingId, CancellationToken ct = default)
    {
        var data = await _api.GetAsync(
            $"/verify/{Uri.EscapeDataString(trackingId)}", ct).ConfigureAwait(false);
        return ApiClient.ParseVerificationReport(data);
    }

    /// <summary>
    /// Download a portable verification proof bundle (bundle_type
    /// "trustbeat.verification.proof"). Returns the raw JSON bundle bytes.
    /// Throws <see cref="NotFoundException"/> if the tracking ID is unknown.
    /// </summary>
    public async Task<byte[]> ExportVerificationAsync(string trackingId, CancellationToken ct = default)
    {
        var (contentType, body) = await _api.GetRawAsync(
            $"/verify/{Uri.EscapeDataString(trackingId)}/export", ct).ConfigureAwait(false);
        ThrowIfErrorBundle(contentType, body, "Verification export failed");
        return body;
    }

    /// <summary>
    /// Validate a standalone X.509 certificate (DER or PEM) against the EU Trusted List.
    /// </summary>
    public async Task<CertificateValidationResult> ValidateCertificateAsync(
        byte[] certificate, CancellationToken ct = default)
    {
        var body = Json.BuildObject(
            ("certificate_base64", Convert.ToBase64String(certificate)));
        var data = await _api.PostAsync("/validate/certificate", body, ct).ConfigureAwait(false);
        return ApiClient.ParseCertValidationResult(data);
    }

    // ── Webhooks ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Verify the <c>X-TrustBeat-Signature</c> header of a webhook delivery.
    /// Pass the <b>raw request body</b> exactly as received. Returns <c>true</c>
    /// if the signature is valid and the timestamp is within the default
    /// 5-minute tolerance. See <see cref="WebhookVerifier"/> for details.
    /// </summary>
    public static bool VerifyWebhookSignature(byte[] payload, string signatureHeader, string secret)
        => WebhookVerifier.VerifyWebhookSignature(payload, signatureHeader, secret);

    // ── Audit Trail ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Submit a single audit event for tamper-evident Merkle anchoring.
    /// Returns the <c>eventId</c> immediately (202 Accepted).
    /// </summary>
    /// <param name="trailCategory">Logical trail, e.g. "financial".</param>
    /// <param name="actor">Who performed the action, e.g. "user:42".</param>
    /// <param name="action">Machine-readable verb, e.g. "payment.approved".</param>
    /// <param name="ts">ISO 8601 timestamp of when the event occurred.</param>
    public async Task<string> SubmitAuditEventAsync(
        string trailCategory, string actor, string action, string ts,
        CancellationToken ct = default)
    {
        var body = Json.BuildObject(
            ("trail_category", trailCategory),
            ("actor",          actor),
            ("action",         action),
            ("ts",             ts));
        var data = await _api.PostAsync("/audit/events", body, ct).ConfigureAwait(false);
        return (string) data["event_id"]!;
    }

    /// <summary>
    /// Submit up to 1,000 audit events in a single batch request. Each event uses the
    /// same keys as <see cref="SubmitAuditEventAsync"/> (trail_category, actor, action, ts).
    /// Returns the event IDs in submission order.
    /// </summary>
    public async Task<IReadOnlyList<string>> SubmitAuditEventsAsync(
        IEnumerable<IReadOnlyDictionary<string, object?>> events, CancellationToken ct = default)
    {
        // The API decodes the body as a bare JSON array of events.
        var items = string.Join(",", events.Select(e =>
            Json.BuildObject(e.Select(kv => (kv.Key, kv.Value)).ToArray())));
        var body = "[" + items + "]";
        var data = await _api.PostAsync("/audit/events/batch", body, ct).ConfigureAwait(false);
        return data.TryGetValue("event_ids", out var v) && v is List<object?> list
            ? list.Select(o => o?.ToString() ?? "").ToList()
            : (IReadOnlyList<string>) Array.Empty<string>();
    }

    /// <summary>
    /// Fetch the Merkle inclusion proof for an anchored audit event.
    /// Returns <c>null</c> if the event is not yet anchored.
    /// </summary>
    public async Task<AuditEventProof?> GetAuditEventProofAsync(
        string eventId, CancellationToken ct = default)
    {
        var data = await _api.GetAsync($"/audit/events/{eventId}/proof", ct).ConfigureAwait(false);
        if (data.TryGetValue("status", out var s) && s?.ToString() == "pending") return null;
        return ApiClient.ParseAuditEventProof(data);
    }

    /// <summary>
    /// Query audit events with optional filters. Returns one page of results.
    /// </summary>
    public async Task<IReadOnlyList<AuditEvent>> ListAuditEventsAsync(
        string? trailCategory = null, int page = 1, int pageSize = 25,
        CancellationToken ct = default)
    {
        var qs = $"/audit/events?page={page}&page_size={pageSize}";
        if (trailCategory is not null) qs += $"&trail_category={Uri.EscapeDataString(trailCategory)}";
        var data = await _api.GetAsync(qs, ct).ConfigureAwait(false);
        var events = data.TryGetValue("events", out var ev) && ev is List<object?> list
            ? list.OfType<Dictionary<string, object?>>().Select(ApiClient.ParseAuditEvent).ToList().AsReadOnly()
            : (IReadOnlyList<AuditEvent>) Array.Empty<AuditEvent>();
        return events;
    }

    /// <summary>
    /// Export audit events as a court-admissible ZIP package.
    /// Blocks until the export job completes (polls every 3 s, up to 5 min).
    /// </summary>
    public async Task<byte[]> ExportAuditEventsAsync(
        string from, string to, string? trailCategory = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(from) || string.IsNullOrEmpty(to))
            throw new ArgumentException("ExportAuditEventsAsync requires both from and to.");
        var pairs = new List<(string, object?)> { ("from", from), ("to", to) };
        if (trailCategory is not null) pairs.Add(("trail_category", trailCategory));
        var body = Json.BuildObject(pairs.ToArray());
        var jobData = await _api.PostAsync("/audit/export", body, ct).ConfigureAwait(false);
        var jobId = (string) jobData["job_id"]!;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
        while (true)
        {
            var (contentType, bytes) = await _api.GetRawAsync($"/audit/export/{jobId}", ct).ConfigureAwait(false);
            if (contentType.StartsWith("application/zip")) return bytes;
            var status = Json.ParseObject(System.Text.Encoding.UTF8.GetString(bytes));
            var s = status.TryGetValue("status", out var sv) ? sv?.ToString() : "";
            if (s == "failed") throw new TrustBeatException(
                status.TryGetValue("error", out var err) ? err?.ToString() ?? "Export failed" : "Export failed", 0, null);
            if (DateTimeOffset.UtcNow > deadline) throw new TrustBeatException($"Export job {jobId} timed out", 0, null);
            await Task.Delay(3000, ct).ConfigureAwait(false);
        }
    }

    // ── Tamper-Evident Logs (NIS2) ──────────────────────────────────────────────

    /// <summary>
    /// Submit a log hash for NIS2 Article 21 tamper-evident anchoring. Returns
    /// immediately (202); the log is anchored in the next batch (~10 min).
    /// </summary>
    public async Task<LogAnchorJob> AnchorLogAsync(
        string logHash, LogMetadata metadata, string? label = null, CancellationToken ct = default)
    {
        var body = Json.BuildObject(
            ("log_hash", logHash),
            ("metadata", new Json.RawJson(LogMetadataJson(metadata))),
            ("label",    label));
        var data = await _api.PostAsync("/logs/anchor", body, ct).ConfigureAwait(false);
        return ApiClient.ParseLogAnchorJob(data);
    }

    /// <summary>
    /// Fetch the verification result for a log anchor. Returns <c>null</c> while the
    /// log is still pending (verification_status "PENDING"). Throws
    /// <see cref="NotFoundException"/> if the tracking ID is unknown.
    /// </summary>
    public async Task<LogProof?> GetLogProofAsync(string trackingId, CancellationToken ct = default)
    {
        var data = await _api.GetAsync($"/logs/verify/{Uri.EscapeDataString(trackingId)}", ct).ConfigureAwait(false);
        if (Json.Str(data, "verification_status") == "PENDING") return null;
        return ApiClient.ParseLogProof(data);
    }

    /// <summary>Get the lightweight status of a log anchor submission (cheap polling).</summary>
    public async Task<LogStatus> GetLogStatusAsync(string trackingId, CancellationToken ct = default)
    {
        var data = await _api.GetAsync($"/logs/{Uri.EscapeDataString(trackingId)}/status", ct).ConfigureAwait(false);
        return ApiClient.ParseLogStatus(data);
    }

    /// <summary>List recent log anchor submissions, with optional filters.</summary>
    public async Task<IReadOnlyList<LogAnchorListItem>> ListLogsAsync(
        string? status = null, string? from = null, string? to = null, CancellationToken ct = default)
    {
        var parts = new List<string>();
        if (status is not null) parts.Add($"status={Uri.EscapeDataString(status)}");
        if (from   is not null) parts.Add($"from={Uri.EscapeDataString(from)}");
        if (to     is not null) parts.Add($"to={Uri.EscapeDataString(to)}");
        var qs = parts.Count > 0 ? "?" + string.Join("&", parts) : "";
        var data = await _api.GetAsync($"/logs{qs}", ct).ConfigureAwait(false);
        return Json.Array(data, "logs").Select(ApiClient.ParseLogAnchorListItem).ToList();
    }

    /// <summary>
    /// Download a portable NIS2 log proof bundle (bundle_type "trustbeat.log.proof").
    /// Returns the raw JSON bundle bytes. Throws <see cref="NotFoundException"/> if
    /// the log is unknown or not yet anchored.
    /// </summary>
    public async Task<byte[]> ExportLogAsync(string trackingId, CancellationToken ct = default)
    {
        var (contentType, body) = await _api.GetRawAsync(
            $"/logs/{Uri.EscapeDataString(trackingId)}/export", ct).ConfigureAwait(false);
        ThrowIfErrorBundle(contentType, body, "Log export failed");
        return body;
    }

    // Error responses to bundle downloads come back as JSON {error:{code,message}};
    // surface them as typed exceptions instead of returning the error body.
    private static void ThrowIfErrorBundle(string contentType, byte[] body, string fallbackMessage)
    {
        if (!contentType.StartsWith("application/json")) return;
        var doc = Json.ParseObject(System.Text.Encoding.UTF8.GetString(body));
        if (doc.TryGetValue("error", out var errObj) && errObj is Dictionary<string, object?> err)
        {
            var msg  = Json.Str(err, "message") ?? fallbackMessage;
            var code = Json.Str(err, "code");
            if (code is "NOT_FOUND" or "NOT_ANCHORED") throw new NotFoundException(msg, code);
            throw new TrustBeatException(msg);
        }
    }

    /// <summary>Poll GetLogProofAsync until the log is anchored, then return the proof.</summary>
    public async Task<LogProof> AnchorLogWaitAsync(
        string trackingId, int timeoutSecs = 660, int pollSecs = 15, CancellationToken ct = default)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(timeoutSecs);
        while (true)
        {
            var proof = await GetLogProofAsync(trackingId, ct).ConfigureAwait(false);
            if (proof is not null) return proof;
            if (DateTimeOffset.UtcNow > deadline)
                throw new TrustBeatException($"AnchorLogWait timed out for {trackingId}");
            await Task.Delay(pollSecs * 1000, ct).ConfigureAwait(false);
        }
    }

    private static string LogMetadataJson(LogMetadata m)
    {
        var src = Json.BuildObject(
            ("uri", m.LogSource.Uri), ("name", m.LogSource.Name), ("size_bytes", m.LogSource.SizeBytes));
        var id = m.SourceIdentity;
        var ident = Json.BuildObject(
            ("system_uuid",       id.SystemUuid),
            ("cloud_instance_id", id.CloudInstanceId),
            ("hostname",          id.Hostname),
            ("service_name",      id.ServiceName),
            ("tenant_id",         id.TenantId));
        var pairs = new List<(string, object?)>
        {
            ("log_source",      new Json.RawJson(src)),
            ("source_identity", new Json.RawJson(ident)),
        };
        if (m.TimeEnvelope is not null)
            pairs.Add(("time_envelope", new Json.RawJson(Json.BuildObject(
                ("start_at", m.TimeEnvelope.StartAt), ("end_at", m.TimeEnvelope.EndAt)))));
        return Json.BuildObject(pairs.ToArray());
    }

    public void Dispose() => _api.Dispose();
}

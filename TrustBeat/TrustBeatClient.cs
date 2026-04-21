using System.IO;
using System.Security.Cryptography;
using System.Text;
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
            ("hash_algorithm", "sha256"),
            ("client_ref",     options?.ClientRef),
            ("description",    options?.Description));

        var data = await _api.PostAsync("/anchors", body, ct).ConfigureAwait(false);
        return ApiClient.ParseAnchorJob(data);
    }

    /// <summary>Submit up to 100 SHA-256 hashes in a single batch.</summary>
    public async Task<IReadOnlyList<AnchorJob>> AnchorBatchAsync(
        IReadOnlyList<string> hashes,
        AnchorOptions? options = null,
        CancellationToken ct = default)
    {
        if (hashes.Count == 0) return [];
        if (hashes.Count > 100)
            throw new ArgumentException("AnchorBatch: maximum 100 hashes per request");

        var items = "[" + string.Join(",",
            hashes.Select(h => Json.BuildObject(("hash", h), ("hash_algorithm", "sha256")))) + "]";

        var body = Json.BuildObject(
            ("hashes",      new Json.RawJson(items)),
            ("client_ref",  options?.ClientRef),
            ("description", options?.Description));

        var data = await _api.PostAsync("/anchors/batch", body, ct).ConfigureAwait(false);
        return Json.Array(data, "accepted").Select(ApiClient.ParseAnchorJob).ToList();
    }

    /// <summary>
    /// Retrieve a proof by tracking ID.
    /// Returns <c>null</c> if the anchor is still pending.
    /// </summary>
    public async Task<AnchorProof?> GetProofAsync(string trackingId, CancellationToken ct = default)
    {
        var path = "/anchors/" + Uri.EscapeDataString(trackingId);
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

    /// <summary>Request a direct (non-Merkle) qualified timestamp for a single hash.</summary>
    public async Task<TimestampResult> TimestampAsync(
        string hash,
        AnchorOptions? options = null,
        CancellationToken ct = default)
    {
        var body = Json.BuildObject(
            ("hash",           hash),
            ("hash_algorithm", "sha256"),
            ("client_ref",     options?.ClientRef),
            ("description",    options?.Description));

        var data = await _api.PostAsync("/timestamps", body, ct).ConfigureAwait(false);
        return ApiClient.ParseTimestamp(data);
    }

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

    public void Dispose() => _api.Dispose();
}

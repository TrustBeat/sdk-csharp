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

    public void Dispose() => _api.Dispose();
}

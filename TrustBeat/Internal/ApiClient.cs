using System.Net.Http.Headers;
using System.Text;

namespace TrustBeat.Internal;

/// <summary>
/// Low-level HTTP client wrapping System.Net.Http.HttpClient.
/// Handles auth, serialisation, deserialisation, and error mapping.
/// </summary>
internal sealed class ApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string     _baseUrl;

    internal ApiClient(string apiKey, string baseUrl, TimeSpan timeout)
        : this(apiKey, baseUrl, new HttpClientHandler()) { }

    /// <summary>Test-only constructor that injects a custom message handler.</summary>
    internal ApiClient(string apiKey, string baseUrl, HttpMessageHandler handler)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", apiKey);
        _http.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
    }

    // ── HTTP verbs ─────────────────────────────────────────────────────────────

    internal async Task<Dictionary<string, object?>> PostAsync(
        string path, string jsonBody, CancellationToken ct)
    {
        var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        var response = await _http.PostAsync(_baseUrl + path, content, ct).ConfigureAwait(false);
        return await ReadAsync(response, ct).ConfigureAwait(false);
    }

    internal async Task<Dictionary<string, object?>> GetAsync(
        string path, CancellationToken ct)
    {
        var response = await _http.GetAsync(_baseUrl + path, ct).ConfigureAwait(false);
        return await ReadAsync(response, ct).ConfigureAwait(false);
    }

    private static async Task<Dictionary<string, object?>> ReadAsync(
        HttpResponseMessage response, CancellationToken ct)
    {
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        Dictionary<string, object?> data;
        try   { data = Json.ParseObject(body); }
        catch { data = new Dictionary<string, object?> { ["error"] = new Dictionary<string, object?> { ["message"] = body } }; }

        if (response.IsSuccessStatusCode) return data;

        var msg  = ExtractErrorMessage(data, (int)response.StatusCode);
        var code = ExtractErrorCode(data);
        throw (int)response.StatusCode switch
        {
            401 => new AuthException(msg),
            402 => new QuotaException(msg),
            404 => new NotFoundException(msg, code ?? "NOT_FOUND"),
            429 => new RateLimitException(msg),
            _   => new TrustBeatException(msg, (int)response.StatusCode, code)
        };
    }

    private static string? ExtractErrorCode(Dictionary<string, object?> data)
    {
        if (data.TryGetValue("error", out var err) &&
            err is Dictionary<string, object?> errObj &&
            errObj.TryGetValue("code", out var code) && code is not null)
            return code.ToString();
        return null;
    }

    private static string ExtractErrorMessage(Dictionary<string, object?> data, int status)
    {
        if (data.TryGetValue("error", out var err) &&
            err is Dictionary<string, object?> errObj &&
            errObj.TryGetValue("message", out var msg) && msg is not null)
            return msg.ToString()!;
        return $"HTTP {status}";
    }

    // ── Response parsers ───────────────────────────────────────────────────────

    internal static AnchorJob ParseAnchorJob(Dictionary<string, object?> d) => new(
        Id:            Json.Str(d, "id")!,
        Hash:          Json.Str(d, "hash")!,
        HashAlgorithm: Json.Str(d, "hash_algorithm")!,
        Status:        Json.Str(d, "status")!,
        SubmittedAt:   Json.Str(d, "submitted_at")!,
        Overage:       Json.Bool(d, "overage", false)
    );

    internal static AnchorProof ParseProof(Dictionary<string, object?> d)
    {
        var path = Json.Array(d, "proof_path")
            .Select(s => new ProofStep(Json.Str(s, "sibling")!, Json.Str(s, "side")!))
            .ToList();

        var tokenB64 = Json.Str(d, "token");
        var token    = tokenB64 is not null ? Convert.FromBase64String(tokenB64) : [];

        return new AnchorProof(
            Id:            Json.Str(d, "id")!,
            Hash:          Json.Str(d, "hash")!,
            HashAlgorithm: Json.Str(d, "hash_algorithm")!,
            BatchId:       Json.Str(d, "batch_id")!,
            LeafIndex:     Json.Int(d, "leaf_index"),
            MerkleRoot:    Json.Str(d, "merkle_root")!,
            ProofPath:     path,
            Token:         token,
            TokenFormat:   Json.Str(d, "token_format")!,
            TsaSerial:     Json.Str(d, "tsa_serial")!,
            Provider:      Json.Str(d, "provider")!,
            AnchoredAt:    Json.Str(d, "anchored_at")!,
            ClientRef:     Json.Str(d, "client_ref"),
            Description:   Json.Str(d, "description")
        );
    }

    internal static TimestampResult ParseTimestamp(Dictionary<string, object?> d)
    {
        var tokenB64 = Json.Str(d, "token");
        var token    = tokenB64 is not null ? Convert.FromBase64String(tokenB64) : [];
        return new TimestampResult(
            Id:            Json.Str(d, "id")!,
            Hash:          Json.Str(d, "hash")!,
            HashAlgorithm: Json.Str(d, "hash_algorithm")!,
            Token:         token,
            TokenFormat:   Json.Str(d, "token_format")!,
            TsaSerial:     Json.Str(d, "tsa_serial")!,
            Provider:      Json.Str(d, "provider")!,
            TimestampedAt: Json.Str(d, "timestamped_at")!
        );
    }

    internal static bool LooksLikeProof(Dictionary<string, object?> d)
        => d.ContainsKey("merkle_root") && d["merkle_root"] is not null;

    internal static AiDecisionJob ParseAiDecisionJob(Dictionary<string, object?> d) => new(
        Id:           Json.Str(d, "id")!,
        InputHash:    Json.Str(d, "input_hash")!,
        OutputHash:   Json.Str(d, "output_hash")!,
        CombinedHash: Json.Str(d, "combined_hash")!,
        Status:       Json.Str(d, "status")!,
        SubmittedAt:  Json.Str(d, "submitted_at")!,
        Overage:      Json.Bool(d, "overage", false)
    );

    internal static AiDecisionProof ParseAiDecisionProof(Dictionary<string, object?> d)
    {
        var m  = (d["metadata"] as Dictionary<string, object?>)!;
        var te = (m["time_envelope"] as Dictionary<string, object?>)!;

        var meta = new AiDecisionMetadata(
            ModelId:        Json.Str(m, "model_id")!,
            SystemName:     Json.Str(m, "system_name")!,
            RiskCategory:   Json.Str(m, "risk_category")!,
            DecisionType:   Json.Str(m, "decision_type")!,
            HumanOversight: Json.Bool(m, "human_oversight", false),
            TimeEnvelope:   new AiTimeEnvelope(
                StartedAt:   Json.Str(te, "started_at")!,
                CompletedAt: Json.Str(te, "completed_at")!),
            ModelVersion:        Json.Str(m, "model_version"),
            OperatorId:          Json.Str(m, "operator_id"),
            DeploymentEnv:       Json.Str(m, "deployment_env"),
            ExternalRef:         Json.Str(m, "external_ref"),
            DecisionOutcome:     Json.Str(m, "decision_outcome"),
            ModelArtifactHash:   Json.Str(m, "model_artifact_hash"),
            DataSubjectCategory: Json.Str(m, "data_subject_category")
        );

        AnchorProof? proof = null;
        if (d.TryGetValue("proof", out var proofObj) &&
            proofObj is Dictionary<string, object?> proofDict)
            proof = ParseProof(proofDict);

        return new AiDecisionProof(
            Id:                 Json.Str(d, "id")!,
            InputHash:          Json.Str(d, "input_hash")!,
            OutputHash:         Json.Str(d, "output_hash")!,
            CombinedHash:       Json.Str(d, "combined_hash")!,
            Metadata:           meta,
            VerificationStatus: Json.Str(d, "verification_status")!,
            AnchoredAt:         Json.Str(d, "anchored_at"),
            Proof:              proof
        );
    }

    public void Dispose() => _http.Dispose();
}

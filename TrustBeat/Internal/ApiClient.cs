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
            Description:   Json.Str(d, "description"),
            MerkleAlgorithm: Json.Str(d, "merkle_algorithm") ?? MerkleAlgorithms.LegacySha256,
            TreeSize:      d.ContainsKey("tree_size") && d["tree_size"] is not null
                               ? Json.Int(d, "tree_size")
                               : null
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

    // ── Verification parsers ──────────────────────────────────────────────────

    internal static SignatureDetail ParseSignatureDetail(Dictionary<string, object?> d) => new(
        Index:            Json.Int(d, "index"),
        Qualified:        Json.Bool(d, "qualified", false),
        OnEutl:           Json.Bool(d, "on_eutl", false),
        Qscd:             Json.Bool(d, "qscd", false),
        RevocationStatus: Json.Str(d, "revocation_status")!,
        SignatureLevel:   Json.Str(d, "signature_level")!,
        TimestampPresent: Json.Bool(d, "timestamp_present", false),
        Verdict:          Json.Str(d, "verdict")!,
        SignerName:        Json.Str(d, "signer_name"),
        SignerEmail:       Json.Str(d, "signer_email"),
        SigningTime:       Json.Str(d, "signing_time"),
        CertSerial:        Json.Str(d, "cert_serial"),
        CertFingerprint:   Json.Str(d, "cert_fingerprint"),
        CertIssuer:        Json.Str(d, "cert_issuer"),
        RevocationTime:    Json.Str(d, "revocation_time"),
        OcspResponse:      Json.Str(d, "ocsp_response"),
        TimestampSerial:   Json.Str(d, "timestamp_serial")
    );

    internal static VerificationReport ParseVerificationReport(Dictionary<string, object?> d)
    {
        var signatures = Json.Array(d, "signatures")
                             .Select(ParseSignatureDetail)
                             .ToList()
                             .AsReadOnly();
        return new VerificationReport(
            Verdict:      Json.Str(d, "verdict")!,
            Signatures:   signatures,
            DocumentHash: Json.Str(d, "document_hash")!,
            CheckedAt:    Json.Str(d, "checked_at")!,
            EutlVersion:  Json.Str(d, "eutl_version"),
            TrackingId:   Json.Str(d, "tracking_id")
        );
    }

    internal static VerificationJob ParseVerificationJob(Dictionary<string, object?> d) => new(
        TrackingId:   Json.Str(d, "tracking_id")!,
        DocumentHash: Json.Str(d, "document_hash")!,
        Status:       Json.Str(d, "status")!,
        SubmittedAt:  Json.Str(d, "submitted_at")!
    );

    internal static CertificateValidationResult ParseCertValidationResult(Dictionary<string, object?> d)
    {
        var keyUsageRaw = d.TryGetValue("key_usage", out var ku) && ku is List<object?> list
            ? list.OfType<string>().ToList().AsReadOnly()
            : (IReadOnlyList<string>) Array.Empty<string>();
        return new CertificateValidationResult(
            Subject:          Json.Str(d, "subject")!,
            Issuer:           Json.Str(d, "issuer")!,
            Serial:           Json.Str(d, "serial")!,
            NotBefore:        Json.Str(d, "not_before")!,
            NotAfter:         Json.Str(d, "not_after")!,
            Qualified:        Json.Bool(d, "qualified", false),
            OnEutl:           Json.Bool(d, "on_eutl", false),
            Qscd:             Json.Bool(d, "qscd", false),
            RevocationStatus: Json.Str(d, "revocation_status")!,
            RevocationTime:   Json.Str(d, "revocation_time"),
            KeyUsage:         keyUsageRaw,
            Valid:             Json.Bool(d, "valid", false),
            ValidatedAt:      Json.Str(d, "validated_at")!
        );
    }

    // returns (contentType, bytes) — caller decides
    internal async Task<(string ContentType, byte[] Body)> GetRawAsync(string path, CancellationToken ct)
    {
        var response = await _http.GetAsync(_baseUrl + path, ct).ConfigureAwait(false);
        var ct2 = response.Content.Headers.ContentType?.MediaType ?? "";
        var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        return (ct2, bytes);
    }

    internal static AuditEvent ParseAuditEvent(Dictionary<string, object?> d) => new(
        EventId:       Json.Str(d, "event_id")!,
        TrailCategory: Json.Str(d, "trail_category")!,
        Actor:         Json.Str(d, "actor")!,
        Action:        Json.Str(d, "action")!,
        Ts:            Json.Str(d, "ts")!,
        ReceivedAt:    Json.Str(d, "received_at")!,
        Anchored:      Json.Bool(d, "anchored", false),
        System:        Json.Str(d, "system"),
        Resource:      Json.Str(d, "resource")
    );

    internal static AuditEventProof ParseAuditEventProof(Dictionary<string, object?> d)
    {
        var rawPath = d.TryGetValue("merkle_path", out var mp) && mp is List<object?> list
            ? list.OfType<Dictionary<string, object?>>()
                  .Select(s => new AuditProofStep(Json.Str(s, "sibling")!, Json.Str(s, "side")!))
                  .ToList().AsReadOnly()
            : (IReadOnlyList<AuditProofStep>) Array.Empty<AuditProofStep>();
        return new AuditEventProof(
            EventId:       Json.Str(d, "event_id")!,
            CanonicalHash: Json.Str(d, "canonical_hash")!,
            BatchId:       Json.Str(d, "batch_id")!,
            LeafIndex:     Json.Int(d, "leaf_index"),
            MerklePath:    rawPath,
            AnchoredAt:    Json.Str(d, "anchored_at")!,
            MerkleRoot:    Json.Str(d, "merkle_root"),
            TreeSize:      d.TryGetValue("tree_size", out var ts) && ts is not null
                               ? Json.Int(d, "tree_size") : null,
            MerkleAlgorithm: string.IsNullOrEmpty(Json.Str(d, "merkle_algorithm"))
                               ? MerkleAlgorithms.LegacySha256
                               : Json.Str(d, "merkle_algorithm")!
        );
    }

    internal static AuditExportJob ParseAuditExportJob(Dictionary<string, object?> d)
    {
        var ec = d.TryGetValue("event_count", out var ecv) && ecv is not null ? (int?) Json.Int(d, "event_count") : null;
        return new AuditExportJob(
            JobId:      Json.Str(d, "job_id")!,
            Status:     Json.Str(d, "status")!,
            EventCount: ec,
            Error:      Json.Str(d, "error")
        );
    }

    // ── Tamper-Evident Logs (NIS2) ──────────────────────────────────────────────

    internal static LogAnchorJob ParseLogAnchorJob(Dictionary<string, object?> d) => new(
        Id:           Json.Str(d, "id")!,
        LogHash:      Json.Str(d, "log_hash")!,
        CombinedHash: Json.Str(d, "combined_hash")!,
        Status:       Json.Str(d, "status")!,
        SubmittedAt:  Json.Str(d, "submitted_at")!,
        Overage:      Json.Bool(d, "overage", false),
        Label:        Json.Str(d, "label")
    );

    internal static LogStatus ParseLogStatus(Dictionary<string, object?> d) => new(
        Id:          Json.Str(d, "id")!,
        Status:      Json.Str(d, "status")!,
        SubmittedAt: Json.Str(d, "submitted_at")!,
        AnchoredAt:  Json.Str(d, "anchored_at")
    );

    internal static LogAnchorListItem ParseLogAnchorListItem(Dictionary<string, object?> d) => new(
        Id:           Json.Str(d, "id")!,
        LogHash:      Json.Str(d, "log_hash")!,
        Status:       Json.Str(d, "status")!,
        SubmittedAt:  Json.Str(d, "submitted_at")!,
        LogSourceUri: Json.Str(d, "log_source_uri")!,
        AnchoredAt:   Json.Str(d, "anchored_at"),
        ServiceName:  Json.Str(d, "service_name"),
        Label:        Json.Str(d, "label")
    );

    internal static LogProof ParseLogProof(Dictionary<string, object?> d)
    {
        var meta = ParseLogMetadata((d["metadata"] as Dictionary<string, object?>)!);

        AnchorProof? proof = null;
        if (d.TryGetValue("proof", out var proofObj) && proofObj is Dictionary<string, object?> proofDict)
            proof = ParseProof(proofDict);

        IReadOnlyList<string>? failures = null;
        if (d.TryGetValue("failure_reasons", out var fr) && fr is List<object?> frList)
            failures = frList.Select(o => o?.ToString() ?? "").ToList().AsReadOnly();

        return new LogProof(
            Id:                 Json.Str(d, "id")!,
            LogHash:            Json.Str(d, "log_hash")!,
            Metadata:           meta,
            CombinedHash:       Json.Str(d, "combined_hash")!,
            VerificationStatus: Json.Str(d, "verification_status")!,
            ArchiveStampsCount: Json.Int(d, "archive_stamps_count"),
            AnchoredAt:         Json.Str(d, "anchored_at"),
            Proof:              proof,
            FailureReasons:     failures
        );
    }

    private static LogMetadata ParseLogMetadata(Dictionary<string, object?> m)
    {
        var src = (m["log_source"] as Dictionary<string, object?>)!;
        var ident = m.TryGetValue("source_identity", out var iv) && iv is Dictionary<string, object?> idd
            ? idd : new Dictionary<string, object?>();
        long? size = src.ContainsKey("size_bytes") ? Json.Int(src, "size_bytes") : (long?) null;

        var logSource = new LogSource(Json.Str(src, "uri")!, Json.Str(src, "name"), size);
        var identity = new LogSourceIdentity(
            SystemUuid:      Json.Str(ident, "system_uuid"),
            CloudInstanceId: Json.Str(ident, "cloud_instance_id"),
            Hostname:        Json.Str(ident, "hostname"),
            ServiceName:     Json.Str(ident, "service_name"),
            TenantId:        Json.Str(ident, "tenant_id"));

        LogTimeEnvelope? te = null;
        if (m.TryGetValue("time_envelope", out var tev) && tev is Dictionary<string, object?> ted)
            te = new LogTimeEnvelope(Json.Str(ted, "start_at")!, Json.Str(ted, "end_at")!);

        return new LogMetadata(logSource, identity, te);
    }

    public void Dispose() => _http.Dispose();
}

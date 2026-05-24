namespace TrustBeat;

/// <summary>One step in a Merkle inclusion proof path.</summary>
/// <param name="Sibling">Hex-encoded SHA-256 hash of the sibling node.</param>
/// <param name="Side">Position of the sibling: "left" or "right".</param>
public sealed record ProofStep(string Sibling, string Side);

/// <summary>
/// Represents a pending or completed anchoring job.
/// Returned by <see cref="TrustBeatClient.AnchorAsync"/> and <see cref="TrustBeatClient.AnchorBatchAsync"/>.
/// </summary>
public sealed record AnchorJob(
    string Id,
    string Hash,
    string HashAlgorithm,
    string Status,
    string SubmittedAt,
    bool   Overage
);

/// <summary>
/// Full Merkle inclusion proof, returned once anchoring is complete.
/// Use <see cref="TrustBeatClient.Verify"/> to verify the proof locally.
/// </summary>
public sealed record AnchorProof(
    string           Id,
    string           Hash,
    string           HashAlgorithm,
    string           BatchId,
    int              LeafIndex,
    string           MerkleRoot,
    IReadOnlyList<ProofStep> ProofPath,
    /// <summary>Raw DER-encoded RFC 3161 TimeStampToken bytes.</summary>
    byte[]           Token,
    string           TokenFormat,
    string           TsaSerial,
    string           Provider,
    string           AnchoredAt,
    string?          ClientRef,
    string?          Description
);

/// <summary>Options for anchor and timestamp requests.</summary>
public sealed class AnchorOptions
{
    /// <summary>Your own reference ID, stored and echoed back in proof responses.</summary>
    public string? ClientRef   { get; init; }

    /// <summary>Human-readable description of the content being anchored.</summary>
    public string? Description { get; init; }
}

/// <summary>Options for <see cref="TrustBeatClient.AnchorWaitAsync"/>.</summary>
public sealed class AnchorWaitOptions
{
    /// <summary>Maximum seconds to wait for a proof. Default: 660 (11 min).</summary>
    public int TimeoutSecs      { get; init; } = 660;

    /// <summary>Polling interval in seconds. Default: 15.</summary>
    public int PollIntervalSecs { get; init; } = 15;
}

/// <summary>
/// Returned by <see cref="TrustBeatClient.AnchorBatchAsync"/> — groups all submitted items
/// under a single <see cref="SubmissionId"/> for status polling and proof retrieval.
/// </summary>
public sealed record BatchSubmission(
    string                        SubmissionId,
    IReadOnlyList<AnchorJob>      Items
);

/// <summary>Returned by <see cref="TrustBeatClient.GetBatchStatusAsync"/>.</summary>
public sealed record BatchStatus(
    string SubmissionId,
    int    Total,
    int    Anchored,
    int    Pending
);

// ── AI Act Audit models ───────────────────────────────────────────────────────

/// <summary>Time window of a single AI inference call.</summary>
public sealed record AiTimeEnvelope(
    /// <summary>ISO 8601 timestamp when inference started.</summary>
    string StartedAt,
    /// <summary>ISO 8601 timestamp when inference completed.</summary>
    string CompletedAt
);

/// <summary>
/// Metadata describing an AI decision for EU AI Act Article 12 anchoring.
/// Privacy-safe: only hashes are sent — raw model inputs and outputs are never uploaded.
/// </summary>
public sealed record AiDecisionMetadata(
    /// <summary>Model identifier, e.g. "claude-3-5-sonnet-20241022".</summary>
    string         ModelId,
    /// <summary>AI system name, e.g. "cv-screening-v2".</summary>
    string         SystemName,
    /// <summary>AI Act Annex III risk category, e.g. "employment".</summary>
    string         RiskCategory,
    /// <summary>Decision type: "classification", "ranking", "recommendation", etc.</summary>
    string         DecisionType,
    /// <summary>True if human oversight per AI Act Article 14 was in place.</summary>
    bool           HumanOversight,
    AiTimeEnvelope TimeEnvelope,
    string?        ModelVersion         = null,
    string?        OperatorId           = null,
    /// <summary>"production", "staging", or "testing".</summary>
    string?        DeploymentEnv        = null,
    /// <summary>Operator's own case/record ID — links proof to a specific decision (Art. 12 traceability).</summary>
    string?        ExternalRef          = null,
    /// <summary>Semantic result of the decision, e.g. "rejected". No PII stored.</summary>
    string?        DecisionOutcome      = null,
    /// <summary>SHA-256 hex of the deployed model weights/checkpoint.</summary>
    string?        ModelArtifactHash    = null,
    /// <summary>Category of data subject, e.g. "job_applicant".</summary>
    string?        DataSubjectCategory  = null
);

/// <summary>Returned immediately (202) when an AI decision is enqueued for anchoring.</summary>
public sealed record AiDecisionJob(
    string Id,
    string InputHash,
    string OutputHash,
    /// <summary>SHA-256(input_bytes ‖ output_bytes ‖ UTF-8(JCS(metadata)))</summary>
    string CombinedHash,
    string Status,
    string SubmittedAt,
    bool   Overage
);

/// <summary>
/// Verification result returned once an AI decision has been anchored.
/// VerificationStatus is "VERIFIED" when the Merkle proof is valid and the
/// combined hash matches.
/// </summary>
public sealed record AiDecisionProof(
    string             Id,
    string             InputHash,
    string             OutputHash,
    string             CombinedHash,
    AiDecisionMetadata Metadata,
    /// <summary>"VERIFIED" or "FAILED".</summary>
    string             VerificationStatus,
    string?            AnchoredAt,
    AnchorProof?       Proof
);

/// <summary>Options for AI decision anchor requests.</summary>
public sealed class AiDecisionOptions
{
    /// <summary>Optional webhook URL called when anchoring completes.</summary>
    public string? CallbackUrl { get; init; }
}

// ── Verification models ───────────────────────────────────────────────────────

/// <summary>Per-signature result within a <see cref="VerificationReport"/>.</summary>
public sealed record SignatureDetail(
    int     Index,
    bool    Qualified,
    bool    OnEutl,
    bool    Qscd,
    string  RevocationStatus,
    string  SignatureLevel,
    bool    TimestampPresent,
    string  Verdict,
    string? SignerName        = null,
    string? SignerEmail       = null,
    string? SigningTime       = null,
    string? CertSerial        = null,
    string? CertFingerprint   = null,
    string? CertIssuer        = null,
    string? RevocationTime    = null,
    string? OcspResponse      = null,
    string? TimestampSerial   = null
);

/// <summary>
/// Full eIDAS signature verification report returned by
/// <see cref="TrustBeatClient.VerifySignatureAsync"/>.
/// </summary>
public sealed record VerificationReport(
    string                 Verdict,
    IReadOnlyList<SignatureDetail> Signatures,
    string                 DocumentHash,
    string                 CheckedAt,
    string?                EutlVersion,
    string?                TrackingId
);

/// <summary>
/// Returned immediately (202) when
/// <see cref="TrustBeatClient.VerifyAndAnchorAsync"/> is called.
/// </summary>
public sealed record VerificationJob(
    string TrackingId,
    string DocumentHash,
    string Status,
    string SubmittedAt
);

/// <summary>Result of <see cref="TrustBeatClient.ValidateCertificateAsync"/>.</summary>
public sealed record CertificateValidationResult(
    string                 Subject,
    string                 Issuer,
    string                 Serial,
    string                 NotBefore,
    string                 NotAfter,
    bool                   Qualified,
    bool                   OnEutl,
    bool                   Qscd,
    string                 RevocationStatus,
    string?                RevocationTime,
    IReadOnlyList<string>  KeyUsage,
    bool                   Valid,
    string                 ValidatedAt
);

/// <summary>Options for verification requests.</summary>
public sealed class VerifyOptions
{
    /// <summary>Optional webhook URL called when anchoring completes.</summary>
    public string? CallbackUrl { get; init; }
}

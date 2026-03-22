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

/// <summary>
/// Result of a direct (non-Merkle) qualified timestamp call.
/// Returned by <see cref="TrustBeatClient.TimestampAsync"/>.
/// </summary>
public sealed record TimestampResult(
    string Id,
    string Hash,
    string HashAlgorithm,
    /// <summary>Raw DER-encoded RFC 3161 TimeStampToken bytes.</summary>
    byte[] Token,
    string TokenFormat,
    string TsaSerial,
    string Provider,
    string TimestampedAt
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

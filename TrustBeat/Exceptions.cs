namespace TrustBeat;

/// <summary>Base exception for all TrustBeat SDK errors.</summary>
public class TrustBeatException : Exception
{
    /// <summary>HTTP status code, or 0 if not applicable.</summary>
    public int Status { get; }

    /// <summary>Machine-readable error code returned by the API, or null.</summary>
    public string? Code { get; }

    public TrustBeatException(string message, int status = 0, string? code = null)
        : base(message)
    {
        Status = status;
        Code   = code;
    }
}

/// <summary>401 — invalid or missing API key.</summary>
public sealed class AuthException : TrustBeatException
{
    public AuthException(string message) : base(message, 401, "UNAUTHORIZED") { }
}

/// <summary>404 — tracking ID not found (or not yet anchored — check Code for "NOT_ANCHORED").</summary>
public sealed class NotFoundException : TrustBeatException
{
    public NotFoundException(string message, string code = "NOT_FOUND")
        : base(message, 404, code) { }
}

/// <summary>402 — monthly quota exceeded.</summary>
public sealed class QuotaException : TrustBeatException
{
    public QuotaException(string message) : base(message, 402, "QUOTA_EXCEEDED") { }
}

/// <summary>429 — too many requests.</summary>
public sealed class RateLimitException : TrustBeatException
{
    public RateLimitException(string message) : base(message, 429, "RATE_LIMITED") { }
}

/// <summary>Raised when local Merkle proof verification encounters malformed data.</summary>
/// <summary>
/// Thrown when a proof declares a <c>merkle_algorithm</c> this SDK version does not
/// implement.
///
/// Deliberately not a <see cref="VerificationException"/> and never a <c>false</c>
/// return: "I cannot check this proof" must not be mistaken for "this proof is
/// forged". Upgrade the SDK, or verify server-side via the API.
/// </summary>
public sealed class UnsupportedAlgorithmException : TrustBeatException
{
    public UnsupportedAlgorithmException(string message) : base(message) { }
}

/// <summary>
/// Thrown when a proof does not carry the fields needed to check it locally.
///
/// Audit event proofs from servers older than API 1.46 have no <c>MerkleRoot</c>,
/// so there is nothing to fold the path against. Like
/// <see cref="UnsupportedAlgorithmException"/> this is deliberately not a
/// <see cref="VerificationException"/> and never a <c>false</c> return: "I cannot
/// check this proof" must not be mistaken for "this proof is forged". Verify
/// server-side via the API, or upgrade the server.
/// </summary>
public sealed class IncompleteProofException : TrustBeatException
{
    public IncompleteProofException(string message) : base(message) { }
}

public sealed class VerificationException : TrustBeatException
{
    public VerificationException(string message) : base(message) { }
}

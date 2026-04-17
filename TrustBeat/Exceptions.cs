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
public sealed class VerificationException : TrustBeatException
{
    public VerificationException(string message) : base(message) { }
}

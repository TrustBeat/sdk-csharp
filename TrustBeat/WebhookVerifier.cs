using System.Security.Cryptography;
using System.Text;

namespace TrustBeat;

/// <summary>
/// Webhook signature verification — no network call.
/// <para>
/// TrustBeat signs every webhook delivery for accounts with a webhook secret
/// configured. Each request carries the header:
/// <c>X-TrustBeat-Signature: t=&lt;unix_ts&gt;,v1=&lt;hex(HMAC-SHA256(secret, "&lt;ts&gt;.&lt;body&gt;"))&gt;</c>
/// </para>
/// <para>
/// The HMAC key is the UTF-8 bytes of the secret string exactly as shown in
/// the dashboard (it is <b>not</b> hex-decoded first). The signed payload is
/// the ASCII timestamp, a literal <c>.</c>, and the raw request body bytes.
/// A constant-time comparison is used for the signature check; the timestamp
/// bounds the window for replaying a captured delivery (default 5 minutes).
/// </para>
/// </summary>
public static class WebhookVerifier
{
    /// <summary>Default replay tolerance in seconds (5 minutes).</summary>
    public const long DefaultToleranceSecs = 300;

    /// <summary>
    /// Verify the <c>X-TrustBeat-Signature</c> header of a webhook delivery.
    /// <para>
    /// Pass the <b>raw request body</b> exactly as received — do not
    /// re-serialize the JSON, as any formatting difference changes the signature.
    /// </para>
    /// </summary>
    /// <param name="payload">Raw request body bytes as received.</param>
    /// <param name="signatureHeader">Value of the <c>X-TrustBeat-Signature</c> header.</param>
    /// <param name="secret">Webhook secret from your TrustBeat dashboard.</param>
    /// <param name="toleranceSecs">Max allowed |now - t| in seconds (default 300).</param>
    /// <param name="nowEpochSecs">Override the current unix time (for testing).</param>
    /// <returns>
    /// <c>true</c> if the signature is valid and the timestamp is within
    /// tolerance; <c>false</c> on signature mismatch or a timestamp outside
    /// the tolerance window (possible replay).
    /// </returns>
    /// <exception cref="VerificationException">The header or secret is malformed.</exception>
    public static bool VerifyWebhookSignature(
        byte[] payload,
        string signatureHeader,
        string secret,
        long   toleranceSecs = DefaultToleranceSecs,
        long?  nowEpochSecs  = null)
    {
        if (string.IsNullOrEmpty(secret))
            throw new VerificationException("Webhook secret must not be empty");
        if (string.IsNullOrEmpty(signatureHeader))
            throw new VerificationException("Signature header must not be empty");

        string? tsStr = null;
        string? sigHex = null;
        foreach (var part in signatureHeader.Split(','))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var key = part[..eq].Trim();
            var value = part[(eq + 1)..];
            if (key == "t") tsStr = value;
            else if (key == "v1") sigHex = value;
        }
        if (string.IsNullOrEmpty(tsStr) || string.IsNullOrEmpty(sigHex))
            throw new VerificationException(
                $"Malformed signature header (expected 't=<ts>,v1=<hex>'): {signatureHeader}");
        if (!long.TryParse(tsStr, out var ts))
            throw new VerificationException($"Malformed signature timestamp: {tsStr}");

        var now = nowEpochSecs ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs(now - ts) > toleranceSecs) return false;

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var signed = Encoding.UTF8.GetBytes($"{tsStr}.").Concat(payload).ToArray();
        var expected = Convert.ToHexString(hmac.ComputeHash(signed)).ToLowerInvariant();

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(sigHex.ToLowerInvariant()));
    }

    /// <summary>String-payload convenience overload (UTF-8 encoded before verification).</summary>
    public static bool VerifyWebhookSignature(
        string payload,
        string signatureHeader,
        string secret,
        long   toleranceSecs = DefaultToleranceSecs,
        long?  nowEpochSecs  = null)
        => VerifyWebhookSignature(
            Encoding.UTF8.GetBytes(payload), signatureHeader, secret, toleranceSecs, nowEpochSecs);
}

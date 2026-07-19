using System.Security.Cryptography;
using System.Text;

namespace TrustBeat.Tests;

/// <summary>
/// Unit tests for webhook signature verification — fully offline.
/// Signatures are constructed exactly the way the server builds them
/// (WebhookDispatcher.scala): hex(HMAC-SHA256(utf8(secret), "&lt;ts&gt;.&lt;body&gt;")).
/// </summary>
public class WebhookVerifierTests
{
    private const string Secret = "abababababababababababababababababababababababababababababababab";
    private const long Now = 1_752_000_000L;

    private static readonly byte[] Body =
        Encoding.UTF8.GetBytes("""{"event":"anchor.completed","id":"track-1","hash":"aa"}""");

    private static string Sign(byte[] body, byte[] key, long ts)
    {
        using var hmac = new HMACSHA256(key);
        var signed = Encoding.UTF8.GetBytes($"{ts}.").Concat(body).ToArray();
        var hex = Convert.ToHexString(hmac.ComputeHash(signed)).ToLowerInvariant();
        return $"t={ts},v1={hex}";
    }

    private static string Sign(byte[] body, long ts) => Sign(body, Encoding.UTF8.GetBytes(Secret), ts);

    [Fact]
    public void ValidSignatureAccepted()
        => Assert.True(WebhookVerifier.VerifyWebhookSignature(Body, Sign(Body, Now), Secret, nowEpochSecs: Now));

    [Fact]
    public void StringPayloadEquivalentToBytes()
        => Assert.True(WebhookVerifier.VerifyWebhookSignature(
            Encoding.UTF8.GetString(Body), Sign(Body, Now), Secret, nowEpochSecs: Now));

    [Fact]
    public void KeyIsUtf8OfSecretNotDecodedHex()
    {
        // Signing with the hex-decoded secret must NOT verify.
        var header = Sign(Body, Convert.FromHexString(Secret), Now);
        Assert.False(WebhookVerifier.VerifyWebhookSignature(Body, header, Secret, nowEpochSecs: Now));
    }

    [Fact]
    public void TamperedPayloadRejected()
    {
        var header = Sign(Body, Now);
        var tampered = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(Body).Replace("track-1", "track-2"));
        Assert.False(WebhookVerifier.VerifyWebhookSignature(tampered, header, Secret, nowEpochSecs: Now));
    }

    [Fact]
    public void WrongSecretRejected()
        => Assert.False(WebhookVerifier.VerifyWebhookSignature(
            Body, Sign(Body, Now), new string('c', 64), nowEpochSecs: Now));

    [Fact]
    public void UppercaseHexAccepted()
    {
        var header = Sign(Body, Now);
        var v1 = header.IndexOf("v1=", StringComparison.Ordinal) + 3;
        var upper = header[..v1] + header[v1..].ToUpperInvariant();
        Assert.True(WebhookVerifier.VerifyWebhookSignature(Body, upper, Secret, nowEpochSecs: Now));
    }

    // ── Replay window ─────────────────────────────────────────────────────────

    [Fact]
    public void StaleTimestampRejected()
        => Assert.False(WebhookVerifier.VerifyWebhookSignature(
            Body, Sign(Body, Now - 301), Secret, nowEpochSecs: Now));

    [Fact]
    public void FutureTimestampRejected()
        => Assert.False(WebhookVerifier.VerifyWebhookSignature(
            Body, Sign(Body, Now + 301), Secret, nowEpochSecs: Now));

    [Fact]
    public void ToleranceBoundaryAccepted()
        => Assert.True(WebhookVerifier.VerifyWebhookSignature(
            Body, Sign(Body, Now - 300), Secret, nowEpochSecs: Now));

    [Fact]
    public void CustomToleranceHonoured()
    {
        var header = Sign(Body, Now - 500);
        Assert.False(WebhookVerifier.VerifyWebhookSignature(Body, header, Secret, nowEpochSecs: Now));
        Assert.True(WebhookVerifier.VerifyWebhookSignature(
            Body, header, Secret, toleranceSecs: 600, nowEpochSecs: Now));
    }

    // ── Malformed input ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("v1=abc")]
    [InlineData("t=123")]
    [InlineData("t=abc,v1=def")]
    [InlineData("nonsense")]
    public void MalformedHeaderThrows(string bad)
        => Assert.Throws<VerificationException>(
            () => WebhookVerifier.VerifyWebhookSignature(Body, bad, Secret, nowEpochSecs: Now));

    [Fact]
    public void EmptySecretThrows()
        => Assert.Throws<VerificationException>(
            () => WebhookVerifier.VerifyWebhookSignature(Body, Sign(Body, Now), "", nowEpochSecs: Now));

    [Fact]
    public void ExtraHeaderPartsTolerated()
    {
        // Future-proofing: unknown scheme versions (e.g. v2=…) must not break v1.
        var header = Sign(Body, Now) + ",v2=futurestuff";
        Assert.True(WebhookVerifier.VerifyWebhookSignature(Body, header, Secret, nowEpochSecs: Now));
    }

    // ── Client static method ──────────────────────────────────────────────────

    [Fact]
    public void ClientStaticMethodDelegates()
    {
        var fresh = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.True(TrustBeatClient.VerifyWebhookSignature(Body, Sign(Body, fresh), Secret));
    }
}

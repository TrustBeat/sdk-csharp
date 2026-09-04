using System.Security.Cryptography;
using System.Text;
using TrustBeat;
using TrustBeat.Internal;
using Xunit;

namespace TrustBeat.Tests;

/// <summary>
/// Local verification of audit event proofs, and the compatibility rule that
/// matters most: a proof from a server older than API 1.46 has no merkle_root and
/// must be reported as "cannot check" rather than "invalid".
/// </summary>
public class AuditEventVerifyTests
{
    private static byte[] Sha(byte[] b) => SHA256.HashData(b);
    private static byte[] Cat(params byte[][] parts)
    {
        var outBuf = new byte[parts.Sum(p => p.Length)];
        int i = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, outBuf, i, p.Length); i += p.Length; }
        return outBuf;
    }
    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static AuditEventProof Rfc6962Proof(string? rootOverride = null, string? algorithm = null)
    {
        var a  = Sha(Encoding.UTF8.GetBytes("audit-a"));
        var b  = Sha(Encoding.UTF8.GetBytes("audit-b"));
        var la = Sha(Cat(new byte[] { 0x00 }, a));
        var lb = Sha(Cat(new byte[] { 0x00 }, b));
        var root = Sha(Cat(new byte[] { 0x01 }, la, lb));
        return new AuditEventProof(
            EventId:       "evt_1",
            CanonicalHash: Hex(a),
            BatchId:       "batch_1",
            LeafIndex:     0,
            MerklePath:    new[] { new AuditProofStep(Hex(lb), "right") },
            AnchoredAt:    "2026-01-01T00:00:00Z",
            MerkleRoot:    rootOverride ?? Hex(root),
            TreeSize:      2,
            MerkleAlgorithm: algorithm ?? MerkleAlgorithms.Rfc6962Sha256);
    }

    [Fact]
    public void AValidRfc6962AuditProofVerifies() =>
        Assert.True(MerkleVerifier.VerifyAuditEvent(Rfc6962Proof()));

    [Fact]
    public void ATamperedRootDoesNotVerify() =>
        Assert.False(MerkleVerifier.VerifyAuditEvent(Rfc6962Proof(rootOverride: new string('a', 64))));

    [Fact]
    public void ALegacyAuditProofVerifiesUnderTheLegacyFold()
    {
        var a = Sha(Encoding.UTF8.GetBytes("audit-a"));
        var b = Sha(Encoding.UTF8.GetBytes("audit-b"));
        var p = new AuditEventProof(
            "evt_1", Hex(a), "batch_1", 0,
            new[] { new AuditProofStep(Hex(b), "right") },
            "2026-01-01T00:00:00Z", Hex(Sha(Cat(a, b))), 2, MerkleAlgorithms.LegacySha256);
        Assert.True(MerkleVerifier.VerifyAuditEvent(p));
    }

    // ── Compatibility with the API currently in production ──────────────────

    /// Exactly what api.trustbeat.eu returns today: no merkle_root, tree_size or algorithm.
    private static AuditEventProof OldServerProof() =>
        ApiClient.ParseAuditEventProof(new Dictionary<string, object?>
        {
            ["event_id"]       = "evt_old",
            ["canonical_hash"] = new string('a', 64),
            ["batch_id"]       = "batch_old",
            ["leaf_index"]     = 0,
            ["merkle_path"]    = new List<object?>
            {
                new Dictionary<string, object?> { ["sibling"] = new string('c', 64), ["side"] = "right" },
            },
            ["anchored_at"]    = "2026-01-01T00:00:00Z",
        });

    [Fact]
    public void AnOldServerProofStillParsesAndDefaultsToLegacy()
    {
        var p = OldServerProof();
        Assert.Equal("evt_old", p.EventId);
        Assert.Single(p.MerklePath);
        Assert.Null(p.MerkleRoot);
        Assert.Null(p.TreeSize);
        Assert.Equal(MerkleAlgorithms.LegacySha256, p.MerkleAlgorithm);
    }

    [Fact]
    public void AnOldServerProofIsIncompleteNotInvalid()
    {
        // Returning false here would tell a customer their perfectly good audit
        // proof had been tampered with.
        var e = Assert.Throws<IncompleteProofException>(
            () => MerkleVerifier.VerifyAuditEvent(OldServerProof()));
        Assert.IsNotType<VerificationException>(e);
        Assert.Contains("merkle_root", e.Message);
    }

    [Fact]
    public void AnUnknownAlgorithmIsUnsupportedNotInvalid() =>
        Assert.Throws<UnsupportedAlgorithmException>(
            () => MerkleVerifier.VerifyAuditEvent(Rfc6962Proof(algorithm: "sha3-future")));
}

using System.Security.Cryptography;
using TrustBeat.Internal;
using Xunit;

namespace TrustBeat.Tests;

/// <summary>Verification dispatch on the proof's declared merkle_algorithm (SDK 0.4.0).</summary>
public class MerkleAlgorithmDispatchTests
{
    private static byte[] Sha(params byte[][] parts)
    {
        var buf = parts.SelectMany(p => p).ToArray();
        return SHA256.HashData(buf);
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static AnchorProof Proof(string hash, string root,
                                     IReadOnlyList<ProofStep> path, string? algorithm)
        => new("p1", hash, "SHA-256", "b1", 0, root, path, [], "RFC3161_DER", "1",
               "test", "2026-01-01T00:00:00Z", null, null,
               algorithm ?? MerkleAlgorithms.LegacySha256, null);

    [Fact]
    public void DefaultAlgorithmIsLegacy()
    {
        // Proofs issued before the field existed must keep verifying forever.
        var leaf = Sha("a"u8.ToArray());
        var p = new AnchorProof("p1", Hex(leaf), "SHA-256", "b1", 0, Hex(leaf), [], [],
                                "RFC3161_DER", "1", "test", "2026-01-01T00:00:00Z", null, null);
        Assert.Equal(MerkleAlgorithms.LegacySha256, p.MerkleAlgorithm);
        Assert.True(MerkleVerifier.Verify(p));
    }

    [Fact]
    public void Rfc6962HashesTheLeaf()
    {
        var leaf = Sha("a"u8.ToArray());
        var rfcRoot = Hex(Sha([0x00], leaf));

        Assert.True(MerkleVerifier.Verify(
            Proof(Hex(leaf), rfcRoot, [], MerkleAlgorithms.Rfc6962Sha256)));

        // Under rfc6962 a one-leaf root is not the leaf itself.
        Assert.False(MerkleVerifier.Verify(
            Proof(Hex(leaf), Hex(leaf), [], MerkleAlgorithms.Rfc6962Sha256)));
    }

    [Fact]
    public void Rfc6962ReferenceVector()
    {
        // MTH([SHA256("a"), SHA256("b"), SHA256("c")]) per RFC 6962, leaf 0.
        var a = Sha("a"u8.ToArray());
        ProofStep[] path =
        [
            new("a0d9f0a50b35b9f7d7edc57fb64f4771ddef0fefeaca4e6f949a1514db5b136d", "right"),
            new("6a3fc11b79f836bda340e75c8906e961b8adf4d6a08a2b992e3f38cd6ff38ebf", "right"),
        ];
        const string root = "cac3d448d4e20a2ad5eae1f500e63c2a7f9217cd14572ba7fd22e26dc1ec2648";
        Assert.True(MerkleVerifier.Verify(Proof(Hex(a), root, path, MerkleAlgorithms.Rfc6962Sha256)));
    }

    // Vectors below are taken verbatim from Google's transparency-dev/merkle
    // (rfc6962_test.go) — a third-party implementation. Our own arithmetic only
    // proves self-consistency; these prove conformance.
    private const string UpstreamEntry     = "4c313233343536"; // hex of "L123456"
    private const string UpstreamLeaf      = "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56";
    private const string UpstreamEmptyLeaf = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
    private const string UpstreamRoot2     = "bf9ae70442844df993ca0001a7c8a095c5f145857960b1ee389df6cbe84b5bf3";

    [Fact]
    public void LeafHashMatchesUpstreamVector()
    {
        // SHA-256(0x00 || "L123456") per transparency-dev/merkle.
        Assert.True(MerkleVerifier.Verify(
            Proof(UpstreamEntry, UpstreamLeaf, [], MerkleAlgorithms.Rfc6962Sha256)));
    }

    [Fact]
    public void Rfc6962LeftSiblingAppliesTheNodePrefix()
    {
        // Two-leaf tree whose BOTH leaf hashes are upstream vectors.
        // Exercises side="left", which no other rfc6962 test reaches.
        ProofStep[] path = [new(UpstreamEmptyLeaf, "left")];
        Assert.True(MerkleVerifier.Verify(
            Proof(UpstreamEntry, UpstreamRoot2, path, MerkleAlgorithms.Rfc6962Sha256)));
    }

    [Fact]
    public void UnknownAlgorithmThrowsRatherThanReturningFalse()
    {
        // "I cannot check this" must not look like "this proof is forged".
        var leaf = Sha("a"u8.ToArray());
        Assert.Throws<UnsupportedAlgorithmException>(() =>
            MerkleVerifier.Verify(Proof(Hex(leaf), Hex(leaf), [], "sha3-512-tree")));
    }
}

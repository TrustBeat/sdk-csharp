using System.Security.Cryptography;
using TrustBeat.Internal;

namespace TrustBeat.Tests;

/// <summary>
/// Unit tests for local Merkle proof verification.
///
/// Test vectors mirror MerkleEngine.scala:
///   parent = SHA-256(left_child || right_child)
///   odd layers duplicate the last node.
/// </summary>
public class MerkleVerifierTests
{
    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] H(string text) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text));
    private static byte[] H(byte[] a, byte[] b)
    {
        var buf = new byte[a.Length + b.Length];
        a.CopyTo(buf, 0); b.CopyTo(buf, a.Length);
        return SHA256.HashData(buf);
    }
    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static AnchorProof MakeProof(byte[] leaf, IReadOnlyList<ProofStep> path, byte[] root)
        => new("test-id", Hex(leaf), "sha256", "batch-1", 0, Hex(root),
               path, [], "rfc3161", "0", "test", "2026-01-01T00:00:00Z", null, null);

    // ── 4-leaf tree ───────────────────────────────────────────────────────────
    //   L0   L1   L2   L3
    //   N01=H(L0,L1)   N23=H(L2,L3)
    //   ROOT=H(N01,N23)

    static readonly byte[] L0   = H("leaf0");
    static readonly byte[] L1   = H("leaf1");
    static readonly byte[] L2   = H("leaf2");
    static readonly byte[] L3   = H("leaf3");
    static readonly byte[] N01  = H(L0, L1);
    static readonly byte[] N23  = H(L2, L3);
    static readonly byte[] Root4 = H(N01, N23);

    [Fact] public void Leaf0ProofIsValid() =>
        Assert.True(MerkleVerifier.Verify(MakeProof(L0,
            [new(Hex(L1), "right"), new(Hex(N23), "right")], Root4)));

    [Fact] public void Leaf1ProofIsValid() =>
        Assert.True(MerkleVerifier.Verify(MakeProof(L1,
            [new(Hex(L0), "left"), new(Hex(N23), "right")], Root4)));

    [Fact] public void Leaf2ProofIsValid() =>
        Assert.True(MerkleVerifier.Verify(MakeProof(L2,
            [new(Hex(L3), "right"), new(Hex(N01), "left")], Root4)));

    [Fact] public void Leaf3ProofIsValid() =>
        Assert.True(MerkleVerifier.Verify(MakeProof(L3,
            [new(Hex(L2), "left"), new(Hex(N01), "left")], Root4)));

    [Fact] public void WrongSiblingReturnsFalse() =>
        Assert.False(MerkleVerifier.Verify(MakeProof(L0,
            [new(Hex(L2), "right"), new(Hex(N23), "right")], Root4))); // wrong sibling

    [Fact] public void WrongRootReturnsFalse() =>
        Assert.False(MerkleVerifier.Verify(new AnchorProof(
            "test-id", Hex(L0), "sha256", "batch-1", 0, new string('f', 64),
            [new(Hex(L1), "right"), new(Hex(N23), "right")],
            [], "rfc3161", "0", "test", "2026-01-01T00:00:00Z", null, null)));

    [Fact] public void SwappedSideReturnsFalse() =>
        Assert.False(MerkleVerifier.Verify(MakeProof(L0,
            [new(Hex(L1), "left"), new(Hex(N23), "right")], Root4))); // wrong side

    // ── Single-leaf tree ──────────────────────────────────────────────────────

    [Fact] public void SingleLeafEmptyPathRootEqualsLeaf()
    {
        var leaf = H("only leaf");
        Assert.True(MerkleVerifier.Verify(MakeProof(leaf, [], leaf)));
    }

    // ── Odd-leaf (3-leaf) tree ────────────────────────────────────────────────
    //   La  Lb  Lc  (Lc duplicated)
    //   Nab=H(La,Lb)  Ncc=H(Lc,Lc)
    //   ROOT=H(Nab,Ncc)

    [Fact] public void OddLeafTreeWithDuplicateIsValid()
    {
        var La = H("a"); var Lb = H("b"); var Lc = H("c");
        var Nab = H(La, Lb); var Ncc = H(Lc, Lc); var root = H(Nab, Ncc);
        Assert.True(MerkleVerifier.Verify(MakeProof(Lc,
            [new(Hex(Lc), "right"), new(Hex(Nab), "left")], root)));
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    [Fact] public void MalformedLeafHashThrows()
    {
        var proof = new AnchorProof("id", "not-hex!!", "sha256", "b", 0, Hex(Root4),
                                    [], [], "rfc3161", "0", "t", "2026-01-01T00:00:00Z", null, null);
        var ex = Assert.Throws<VerificationException>(() => MerkleVerifier.Verify(proof));
        Assert.Contains("Invalid leaf hash", ex.Message);
    }

    [Fact] public void MalformedSiblingThrows()
    {
        var proof = MakeProof(L0, [new("gg" + new string('g', 62), "right")], Root4);
        var ex = Assert.Throws<VerificationException>(() => MerkleVerifier.Verify(proof));
        Assert.Contains("Invalid sibling hex", ex.Message);
    }

    [Fact] public void UnknownSideThrows()
    {
        var proof = MakeProof(L0, [new(Hex(L1), "center")], Root4);
        var ex = Assert.Throws<VerificationException>(() => MerkleVerifier.Verify(proof));
        Assert.Contains("Unknown side", ex.Message);
    }

    [Fact] public void MalformedMerkleRootThrows()
    {
        var proof = new AnchorProof("id", Hex(L0), "sha256", "b", 0, "zzzz",
                                    [], [], "rfc3161", "0", "t", "2026-01-01T00:00:00Z", null, null);
        var ex = Assert.Throws<VerificationException>(() => MerkleVerifier.Verify(proof));
        Assert.Contains("Invalid merkle_root", ex.Message);
    }
}

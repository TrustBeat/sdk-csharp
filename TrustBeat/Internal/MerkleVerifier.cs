using System.Security.Cryptography;

namespace TrustBeat.Internal;

/// <summary>
/// Local Merkle inclusion proof verifier.
///
/// Mirrors MerkleEngine.scala exactly:
///   parent = SHA-256(left_child || right_child)
///   side="left"  → sibling on the left  → hash(sibling || current)
///   side="right" → sibling on the right → hash(current || sibling)
///   Odd layers duplicate the last node.
/// </summary>
internal static class MerkleVerifier
{
    internal static bool Verify(AnchorProof proof)
    {
        byte[] current  = DecodeHex(proof.Hash,       "Invalid leaf hash");
        byte[] expected = DecodeHex(proof.MerkleRoot, "Invalid merkle_root");

        foreach (var step in proof.ProofPath)
        {
            byte[] sibling = DecodeHex(step.Sibling, "Invalid sibling hex");
            current = step.Side switch
            {
                "left"  => SHA256.HashData(Concat(sibling, current)),
                "right" => SHA256.HashData(Concat(current, sibling)),
                _ => throw new VerificationException(
                    $"Unknown side: \"{step.Side}\" — expected \"left\" or \"right\"")
            };
        }

        return CryptographicOperations.FixedTimeEquals(current, expected);
    }

    private static byte[] DecodeHex(string? hex, string label)
    {
        if (hex is null || hex.Length % 2 != 0 || !IsHex(hex))
            throw new VerificationException($"{label}: \"{hex}\"");
        return Convert.FromHexString(hex);
    }

    private static bool IsHex(string s)
    {
        foreach (var c in s)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        return true;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result, 0);
        b.CopyTo(result, a.Length);
        return result;
    }
}

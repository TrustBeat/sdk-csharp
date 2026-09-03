using System.Security.Cryptography;

namespace TrustBeat.Internal;

/// <summary>
/// Local Merkle inclusion proof verifier.
///
/// The fold depends on the construction the proof declares:
///   trustbeat-legacy-sha256 — leaf = your hash, parent = SHA-256(left || right)
///   rfc6962-sha256          — leaf = SHA-256(0x00 || your hash),
///                             parent = SHA-256(0x01 || left || right)
///
/// In both, side gives the sibling's position:
///   side="left"  → sibling on the left  → hash over (sibling, current)
///   side="right" → sibling on the right → hash over (current, sibling)
/// </summary>
internal static class MerkleVerifier
{
    internal static bool Verify(AnchorProof proof)
    {
        var algorithm = string.IsNullOrEmpty(proof.MerkleAlgorithm)
            ? MerkleAlgorithms.LegacySha256
            : proof.MerkleAlgorithm;

        byte[] leafPrefix, nodePrefix;
        switch (algorithm)
        {
            case MerkleAlgorithms.LegacySha256:
                leafPrefix = []; nodePrefix = [];
                break;
            case MerkleAlgorithms.Rfc6962Sha256:
                leafPrefix = [0x00]; nodePrefix = [0x01];
                break;
            default:
                throw new UnsupportedAlgorithmException(
                    $"Unsupported merkle_algorithm \"{algorithm}\". This SDK understands " +
                    $"\"{MerkleAlgorithms.LegacySha256}\" and \"{MerkleAlgorithms.Rfc6962Sha256}\". " +
                    "Upgrade the SDK, or verify via the API.");
        }

        byte[] current  = DecodeHex(proof.Hash,       "Invalid leaf hash");
        byte[] expected = DecodeHex(proof.MerkleRoot, "Invalid merkle_root");
        if (leafPrefix.Length > 0) current = SHA256.HashData(Concat(leafPrefix, current));

        foreach (var step in proof.ProofPath)
        {
            byte[] sibling = DecodeHex(step.Sibling, "Invalid sibling hex");
            current = step.Side switch
            {
                "left"  => SHA256.HashData(Concat(nodePrefix, Concat(sibling, current))),
                "right" => SHA256.HashData(Concat(nodePrefix, Concat(current, sibling))),
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

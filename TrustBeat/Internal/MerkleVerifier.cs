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
    /// <summary>
    /// Verify an audit event's Merkle inclusion proof locally. The audit counterpart
    /// of <see cref="Verify(AnchorProof)"/>, for the shape that names the leaf
    /// CanonicalHash and the path MerklePath.
    /// </summary>
    /// <exception cref="IncompleteProofException">
    /// The proof carries no MerkleRoot — servers before API 1.46 did not send one, so
    /// there is nothing to fold against. That is "cannot check", never "invalid".
    /// </exception>
    internal static bool VerifyAuditEvent(AuditEventProof proof)
    {
        if (string.IsNullOrEmpty(proof.MerkleRoot))
        {
            throw new IncompleteProofException(
                "This audit event proof has no merkle_root, so it cannot be folded " +
                "locally. The server that issued it predates API 1.46. Verify it " +
                "server-side via the API, or re-fetch it from an upgraded server.");
        }
        // Reuse the anchor fold: the shapes differ only in field names.
        var path = proof.MerklePath.Select(s => new ProofStep(s.Sibling, s.Side)).ToList();
        return Verify(new AnchorProof(
            Id:              proof.EventId,
            Hash:            proof.CanonicalHash,
            HashAlgorithm:   "SHA-256",
            BatchId:         proof.BatchId,
            LeafIndex:       proof.LeafIndex,
            MerkleRoot:      proof.MerkleRoot!,
            ProofPath:       path,
            Token:           Array.Empty<byte>(),
            TokenFormat:     "",
            TsaSerial:       "",
            Provider:        "",
            AnchoredAt:      proof.AnchoredAt,
            ClientRef:       null,
            Description:     null,
            MerkleAlgorithm: proof.MerkleAlgorithm,
            TreeSize:        proof.TreeSize));
    }

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

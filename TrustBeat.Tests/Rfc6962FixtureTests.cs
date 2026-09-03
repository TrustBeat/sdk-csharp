using System.Text.Json;
using TrustBeat.Internal;
using Xunit;

namespace TrustBeat.Tests;

/// <summary>
/// Agreement with tests/fixtures/rfc6962-proofs.json.
///
/// The same file is checked by the Scala engine and by every other SDK, so this
/// pins cross-implementation agreement rather than self-consistency.
/// </summary>
public class Rfc6962FixtureTests
{
    private static JsonDocument Fixture()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 10 && dir is not null; i++, dir = dir.Parent)
        {
            var f = Path.Combine(dir.FullName, "tests", "fixtures", "rfc6962-proofs.json");
            if (File.Exists(f)) return JsonDocument.Parse(File.ReadAllText(f));
        }
        throw new FileNotFoundException("rfc6962-proofs.json not found");
    }

    private static AnchorProof ToProof(JsonElement e, string? hashOverride = null)
    {
        var steps = e.GetProperty("proof_path").EnumerateArray()
            .Select(s => new ProofStep(s.GetProperty("sibling").GetString()!,
                                       s.GetProperty("side").GetString()!))
            .ToList();
        return new AnchorProof("id", hashOverride ?? e.GetProperty("hash").GetString()!, "SHA-256",
            "b", 0, e.GetProperty("merkle_root").GetString()!, steps, [], "RFC3161_DER", "1",
            "fixture", "2026-01-01T00:00:00Z", null, null,
            e.GetProperty("merkle_algorithm").GetString()!, e.GetProperty("tree_size").GetInt32());
    }

    [Fact]
    public void EveryFixtureProofVerifies()
    {
        using var doc = Fixture();
        var proofs = doc.RootElement.GetProperty("proofs").EnumerateArray().ToList();
        Assert.Equal(7, proofs.Count);
        foreach (var (e, i) in proofs.Select((e, i) => (e, i)))
            Assert.True(MerkleVerifier.Verify(ToProof(e)), $"leaf {i} failed");
    }

    [Fact]
    public void ATamperedFixtureProofFails()
    {
        // Guards against the suite passing because verification is a no-op.
        using var doc = Fixture();
        var first = doc.RootElement.GetProperty("proofs")[0];
        Assert.False(MerkleVerifier.Verify(ToProof(first, new string('0', 64))));
    }
}

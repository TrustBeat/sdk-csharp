// TrustBeat C# SDK smoke CLI — drives the SDK against a LIVE API.
//
// Driven by tests/e2e/sdk_smoke.py (the orchestrator). Built once, then run as
//   dotnet TrustBeat.Smoke.dll <cmd> [id]
// Commands:
//   submit              anchor TB_HASH, print the tracking id
//   verify <id>         fetch the proof via the SDK, check the contract, verify locally
//   submit-batch        anchor a batch from TB_BATCH_SEED/TB_BATCH_N, print submission id
//   verify-batch <id>   fetch batch proofs, check the contract, verify each locally
//
// Env: TB_BASE_URL (includes /v1), TB_API_KEY, TB_HASH, TB_BATCH_SEED, TB_BATCH_N
// Exit 0 on success, non-zero on any failure.

using System.Security.Cryptography;
using System.Text;
using TrustBeat;

if (args.Length < 1)
    Fail("usage: smoke {submit|verify <id>|submit-batch|verify-batch <id>}");

switch (args[0])
{
    case "submit":
    {
        var job = await Client().AnchorAsync(Env("TB_HASH"));
        if (string.IsNullOrEmpty(job.Id)) Fail("submit: empty tracking id");
        Console.WriteLine(job.Id);
        break;
    }
    case "verify":
    {
        if (args.Length < 2) Fail("usage: smoke verify <id>");
        var id = args[1];
        var expected = Environment.GetEnvironmentVariable("TB_HASH");
        var c = Client();
        var proof = await c.GetProofAsync(id);
        if (proof is null) Fail($"verify: proof for {id} not ready");
        if (!string.IsNullOrEmpty(expected) &&
            !string.Equals(proof!.Hash, expected, StringComparison.OrdinalIgnoreCase))
            Fail($"verify: hash echo mismatch {proof!.Hash} != {expected}");
        if (string.IsNullOrEmpty(proof!.MerkleRoot)) Fail("verify: empty merkle_root");
        if (proof.Token is null || proof.Token.Length == 0) Fail("verify: empty token");
        if (!c.Verify(proof)) Fail("verify: local Merkle verification failed");
        Console.WriteLine($"OK id={id} root={proof.MerkleRoot[..16]}… token={proof.Token.Length}B");
        break;
    }
    case "submit-batch":
    {
        var hashes = BatchHashes();
        var sub = await Client().AnchorBatchAsync(hashes);
        if (string.IsNullOrEmpty(sub.SubmissionId)) Fail("submit-batch: empty submission_id");
        if (sub.Items.Count != hashes.Count)
            Fail($"submit-batch: accepted {sub.Items.Count} != {hashes.Count}");
        Console.WriteLine(sub.SubmissionId);
        break;
    }
    case "verify-batch":
    {
        if (args.Length < 2) Fail("usage: smoke verify-batch <id>");
        var sid = args[1];
        var expected = BatchHashes().Select(h => h.ToLowerInvariant()).ToHashSet();
        var c = Client();
        var proofs = await c.GetBatchProofsAsync(sid);
        if (proofs.Count != expected.Count)
            Fail($"verify-batch: got {proofs.Count} proofs, want {expected.Count}");
        foreach (var p in proofs)
        {
            if (!expected.Contains(p.Hash.ToLowerInvariant()))
                Fail($"verify-batch: unexpected proof hash {p.Hash}");
            if (string.IsNullOrEmpty(p.MerkleRoot) || p.Token is null || p.Token.Length == 0)
                Fail($"verify-batch: empty merkle_root/token for {p.Id}");
            if (!c.Verify(p)) Fail($"verify-batch: local Merkle verification failed for {p.Id}");
        }
        Console.WriteLine($"OK batch sid={sid} n={proofs.Count}");
        break;
    }
    default:
        Fail($"unknown command: {args[0]}");
        break;
}

static string Env(string name) => Environment.GetEnvironmentVariable(name)!;

static TrustBeatClient Client() => new(Env("TB_API_KEY"), Env("TB_BASE_URL"));

static List<string> BatchHashes()
{
    var seed = Env("TB_BATCH_SEED");
    var n = int.Parse(Env("TB_BATCH_N"));
    var outp = new List<string>();
    for (int i = 0; i < n; i++)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{seed}::{i}"));
        outp.Add(Convert.ToHexString(bytes).ToLowerInvariant());
    }
    return outp;
}

static void Fail(string msg)
{
    Console.Error.WriteLine(msg);
    Environment.Exit(1);
}

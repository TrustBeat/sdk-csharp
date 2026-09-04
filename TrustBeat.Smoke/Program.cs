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
    case "submit-ai":
    {
        var job = await Client().AnchorAiDecisionAsync(Env("TB_AI_INPUT"), Env("TB_AI_OUTPUT"), AiMeta());
        if (string.IsNullOrEmpty(job.Id)) Fail("submit-ai: empty tracking id");
        Console.WriteLine(job.Id);
        break;
    }
    case "verify-ai":
    {
        if (args.Length < 2) Fail("usage: smoke verify-ai <id>");
        var id = args[1];
        var inHash = Env("TB_AI_INPUT");
        var outHash = Env("TB_AI_OUTPUT");
        var c = Client();
        var proof = await c.GetAiDecisionProofAsync(id);
        if (proof is null) Fail($"verify-ai: proof for {id} not ready");
        if (!string.Equals(proof!.InputHash, inHash, StringComparison.OrdinalIgnoreCase))
            Fail($"verify-ai: input_hash echo mismatch {proof!.InputHash} != {inHash}");
        if (!string.Equals(proof.OutputHash, outHash, StringComparison.OrdinalIgnoreCase))
            Fail($"verify-ai: output_hash echo mismatch {proof.OutputHash} != {outHash}");
        if (proof.VerificationStatus != "VERIFIED")
            Fail($"verify-ai: status {proof.VerificationStatus} != VERIFIED");
        if (proof.Proof is null) Fail("verify-ai: missing Merkle proof");
        if (!c.Verify(proof.Proof!)) Fail("verify-ai: local Merkle verification failed");
        Console.WriteLine($"OK ai id={id} combined={proof.CombinedHash[..16]}…");
        break;
    }
    case "submit-file":
    {
        var job = await Client().AnchorFileAsync(Env("TB_FILE_PATH"));
        if (string.IsNullOrEmpty(job.Id)) Fail("submit-file: empty tracking id");
        Console.WriteLine(job.Id);
        break;
    }
    case "submit-audit":
    {
        var eventId = await Client().SubmitAuditEventAsync(
            Env("TB_AUDIT_CATEGORY"), Env("TB_AUDIT_ACTOR"),
            Env("TB_AUDIT_ACTION"), Env("TB_AUDIT_TS"));
        if (string.IsNullOrEmpty(eventId)) Fail("submit-audit: empty event_id");
        Console.WriteLine(eventId);
        break;
    }
    case "verify-audit":
    {
        if (args.Length < 2) Fail("usage: smoke verify-audit <id>");
        var id = args[1];
        var c = Client();
        var proof = await c.GetAuditEventProofAsync(id);
        if (proof is null) Fail($"verify-audit: proof for {id} not ready");
        if (proof!.EventId != id)
            Fail($"verify-audit: event_id echo mismatch {proof.EventId} != {id}");
        if (string.IsNullOrEmpty(proof.CanonicalHash)) Fail("verify-audit: empty canonical_hash");
        if (string.IsNullOrEmpty(proof.BatchId)) Fail("verify-audit: empty batch_id");
        if (proof.LeafIndex < 0 || proof.MerklePath is null) Fail("verify-audit: invalid leaf_index/merkle_path");
        var events = await c.ListAuditEventsAsync(Env("TB_AUDIT_CATEGORY"));
        if (!events.Any(e => e.EventId == id))
            Fail($"verify-audit: {id} not returned by ListAuditEventsAsync");
        // Actually fold the path — everything above is structure. A server before
        // API 1.46 sends no MerkleRoot, which the SDK reports as "cannot check".
        string verdict;
        try
        {
            if (!c.VerifyAuditEvent(proof)) Fail($"verify-audit: Merkle verification FAILED for {id}");
            verdict = $"verified algo={proof.MerkleAlgorithm} size={proof.TreeSize}";
        }
        catch (IncompleteProofException)
        {
            verdict = "unverifiable (server predates API 1.46)";
        }
        Console.WriteLine($"OK audit id={id} batch={proof.BatchId[..Math.Min(12, proof.BatchId.Length)]}… leaf={proof.LeafIndex} {verdict}");
        break;
    }
    case "verify-sig":
    {
        var doc = await File.ReadAllBytesAsync(Env("TB_SIG_DOC"));
        var expected = Env("TB_SIG_DOCHASH");
        var report = await Client().VerifySignatureAsync(doc, Env("TB_SIG_FORMAT"));
        if (!string.Equals(report.DocumentHash, expected, StringComparison.OrdinalIgnoreCase))
            Fail($"verify-sig: document_hash mismatch {report.DocumentHash} != {expected}");
        if (string.IsNullOrEmpty(report.Verdict)) Fail("verify-sig: empty verdict");
        if (report.Signatures is null || report.Signatures.Count == 0) Fail("verify-sig: report has no signatures");
        Console.WriteLine($"OK sig verdict={report.Verdict} signatures={report.Signatures.Count}");
        break;
    }
    case "validate-cert":
    {
        var cert = await File.ReadAllBytesAsync(Env("TB_CERT_PATH"));
        var res = await Client().ValidateCertificateAsync(cert);
        if (string.IsNullOrEmpty(res.Subject)) Fail("validate-cert: empty subject");
        if (string.IsNullOrEmpty(res.Issuer)) Fail("validate-cert: empty issuer");
        if (string.IsNullOrEmpty(res.ValidatedAt)) Fail("validate-cert: empty validated_at");
        Console.WriteLine($"OK cert subject={res.Subject[..Math.Min(24, res.Subject.Length)]}… qualified={res.Qualified}");
        break;
    }
    default:
        Fail($"unknown command: {args[0]}");
        break;
}

static string Env(string name) => Environment.GetEnvironmentVariable(name)!;

static TrustBeatClient Client() => new(Env("TB_API_KEY"), Env("TB_BASE_URL"));

// Fixed AI-decision metadata — only the input/output hashes vary per run.
static AiDecisionMetadata AiMeta() => new(
    ModelId:        "claude-opus-4-8",
    SystemName:     "trustbeat-sdk-smoke",
    RiskCategory:   "employment",
    DecisionType:   "classification",
    HumanOversight: true,
    TimeEnvelope:   new AiTimeEnvelope("2026-06-29T10:00:00Z", "2026-06-29T10:00:01Z"));

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

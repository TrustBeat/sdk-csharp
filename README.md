# TrustBeat C# / .NET SDK

Qualified electronic timestamps and Merkle anchoring — eIDAS-compliant, over a simple API.

Part of **[TrustBeat](https://trustbeat.eu)** — digital trust infrastructure for the EU.
All SDKs (Python, TypeScript, Java, C#, Go): **[trustbeat.eu/sdks](https://trustbeat.eu/sdks)**.

## Install

```bash
dotnet add package TrustBeat
```

## Quickstart

```csharp
using TrustBeat;

var tb = new TrustBeatClient("tb_live_...");

// Anchor a file (SHA-256 computed locally, file never leaves your machine).
// AnchorFileWaitAsync() blocks until the proof is ready (next batch, up to 11 min).
var proof = await tb.AnchorFileWaitAsync("contract.pdf");
Console.WriteLine(proof.Id);          // tracking ID
Console.WriteLine(proof.AnchoredAt);  // ISO 8601 timestamp
Console.WriteLine(proof.MerkleRoot);  // Merkle root of the batch

// Verify locally — no network call
bool valid = tb.Verify(proof);

// Or anchor a raw SHA-256 hash without blocking, then wait for the proof.
var job = await tb.AnchorAsync("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
var waited = await tb.AnchorWaitAsync(job.Id);  // polls up to 11 min

```

## Tamper-Evident Logs (NIS2)

Anchor a log hash together with canonical metadata for NIS2 Article 21 audit trails.
The server seals the metadata into the Merkle leaf, so the proof covers both the log
content and its context.

```csharp
using TrustBeat;

var tb = new TrustBeatClient("tb_live_...");

// Hash the log yourself — content never leaves your machine.
var logHash = await TrustBeatClient.HashFileAsync("app.log");

var meta = new LogMetadata(
    new LogSource("/var/log/app.log", "Application log"),
    new LogSourceIdentity(Hostname: "web-01", ServiceName: "payments"),
    new LogTimeEnvelope("2026-04-15T00:00:00Z", "2026-04-15T23:59:59Z"));

var job = await tb.AnchorLogAsync(logHash, meta, "incident-2026-05");
Console.WriteLine($"{job.Id} {job.CombinedHash}");

// Wait for the qualified anchor (next batch, up to ~11 min).
var proof = await tb.AnchorLogWaitAsync(job.Id);
Console.WriteLine(proof.VerificationStatus); // "VERIFIED"
```

## Webhooks

If your account has a webhook secret configured, every delivery is signed with
an `X-TrustBeat-Signature` header. Verify it with the raw request body —
before any JSON parsing:

```csharp
var ok = WebhookVerifier.VerifyWebhookSignature(rawBody, signatureHeader, webhookSecret);
if (!ok) throw new UnauthorizedAccessException("Invalid webhook signature");
```

Also available as `TrustBeatClient.VerifyWebhookSignature(...)`. Rejects replays
older than 5 minutes by default (`toleranceSecs` parameter to override).

Portable proof bundles for offline verification: `ExportAiDecisionAsync(id)`,
`ExportVerificationAsync(id)`, `ExportLogAsync(id)` — each returns raw JSON bundle bytes.

## Requirements

- .NET 6+
- Zero runtime dependencies (System.Net.Http, System.Security.Cryptography from stdlib)

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)


### Merkle algorithm

Every proof declares how it must be folded, in `proof.MerkleAlgorithm`:

| Value | Construction |
|---|---|
| `trustbeat-legacy-sha256` | leaf = your hash, parent = `SHA-256(left \|\| right)` |
| `rfc6962-sha256` | leaf = `SHA-256(0x00 \|\| hash)`, parent = `SHA-256(0x01 \|\| left \|\| right)` |

`Verify` dispatches on it for you. A proof with no label was issued before the
field existed and is legacy. An algorithm this SDK version does not implement
throws `UnsupportedAlgorithmException` rather than returning `false` — "cannot
check" is not "invalid".

### Audit event proofs

`VerifyAuditEvent` folds an audit event proof the same way:

```csharp
var proof = await client.GetAuditEventProofAsync(eventId);
try
{
    Console.WriteLine(client.VerifyAuditEvent(proof!));
}
catch (IncompleteProofException)
{
    // The server predates API 1.46 and sent no MerkleRoot, so there is nothing
    // to fold against. The proof is not invalid — verify it server-side instead.
}
```

Treating that exception as a failed proof would be wrong: it means "cannot
check", not "tampered".

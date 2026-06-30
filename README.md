# TrustBeat C# / .NET SDK

Qualified electronic timestamps and Merkle anchoring — eIDAS-compliant, over a simple API.

## Install

```bash
dotnet add package TrustBeat.SDK
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

## Requirements

- .NET 6+
- Zero runtime dependencies (System.Net.Http, System.Security.Cryptography from stdlib)

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)

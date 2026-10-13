using System.Net;
using System.Text;

namespace TrustBeat.Tests;

/// <summary>Signature Preservation: the SDK passes the extractor's submission through and maps the responses.</summary>
public class SignaturePreservationTests
{
    private const string Submission = """{"submission_version":1,"extractor":{"name":"trustbeat-signature","version":"1.0.0"},"container":{"format":"PAdES","name":"contract.pdf","size_bytes":10,"digests":{"sha256":"aa","sha512":"bb","sha3-512":"cc"}},"data_objects":[],"signatures":[{"format":"CAdES","source":"pdf","signature_b64":"MA==","binding":[]}],"timestamps":[]}""";

    private const string Record = """{"id":"01REC","status":"pending","created_at":"2026-10-13T10:00:00Z","client_ref":"contract-17","container":{"format":"PAdES","name":"contract.pdf","sha256":"aa"},"signature_count":1,"peo":{"sha256":"dd","sha512":"ee"},"preservation":{"profile":"https://trustbeat.eu/preservation/profile/pds-wst-v1","profile_status":"draft","preserve_until":"2056-10-13T10:00:00Z"},"evidence_record":{"status":"pending"},"signatures":[{"index":0,"format":"CAdES","indication":"TOTAL_PASSED"}]}""";

    private const string Report = """{"report_version":1,"record_id":"01REC","result":"failed","claim":"At least one step failed.","steps":[{"step":1,"name":"file","title":"The presented file is the preserved file","result":"failed","checked_by":["extractor"],"details":["The digests differ."]}],"signatures":[],"evidence_record":[]}""";

    private sealed record Call(string Method, string Uri, string? ContentType, string? Body);

    private static (TrustBeatClient Client, List<Call> Calls) Client(HttpStatusCode status, string contentType, byte[] body)
    {
        var calls = new List<Call>();
        var client = TrustBeatClientTestFactory.Create(req =>
        {
            calls.Add(new Call(req.Method.Method, req.RequestUri!.PathAndQuery,
                req.Content?.Headers.ContentType?.MediaType, req.Content?.ReadAsStringAsync().Result));
            var content = new ByteArrayContent(body);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
            return new HttpResponseMessage(status) { Content = content };
        });
        return (client, calls);
    }

    private static (TrustBeatClient Client, List<Call> Calls) Json(HttpStatusCode status, string json)
        => Client(status, "application/json", Encoding.UTF8.GetBytes(json));

    [Fact]
    public async Task PreserveSendsTheSubmissionUnchanged()
    {
        var (client, calls) = Json(HttpStatusCode.Accepted, Record);
        var rec = await client.PreserveSignaturesAsync(Submission, "contract 17/a");
        Assert.Equal("POST", calls[0].Method);
        Assert.Equal("/v1/signature-preservation?client_ref=contract%2017%2Fa", calls[0].Uri);
        Assert.Equal("application/json", calls[0].ContentType);
        Assert.Equal(Submission, calls[0].Body);
        Assert.Equal(("01REC", "pending", "PAdES", "dd", "contract-17"),
            (rec.Id, rec.Status, rec.ContainerFormat, rec.PeoSha256, rec.ClientRef));
        Assert.Equal("2056-10-13T10:00:00Z", rec.PreserveUntil);
        Assert.Null(rec.EvidenceRecordUrl);
        Assert.Equal("TOTAL_PASSED", rec.Signatures![0]["indication"]);
    }

    [Fact]
    public async Task ASubmissionMustBeAJsonObject()
    {
        var (client, calls) = Json(HttpStatusCode.Accepted, Record);
        await Assert.ThrowsAsync<ArgumentException>(() => client.PreserveSignaturesAsync("not json"));
        Assert.Empty(calls);
    }

    [Fact]
    public async Task AnInvalidSubmissionCarriesTheCode()
    {
        var (client, _) = Json(HttpStatusCode.BadRequest, """{"error":{"code":"INVALID_SUBMISSION","message":"binding"}}""");
        var e = await Assert.ThrowsAsync<TrustBeatException>(() => client.PreserveSignaturesAsync(Submission));
        Assert.Equal(400, e.Status);
        Assert.Equal("INVALID_SUBMISSION", e.Code);
    }

    [Fact]
    public async Task GetAndList()
    {
        var (client, calls) = Json(HttpStatusCode.OK, Record.Replace("""
            "evidence_record":{"status":"pending"}
            """, """
            "evidence_record":{"status":"ready","download_url":"https://x/evidence-record.ers"}
            """));
        var rec = await client.GetSignaturePreservationAsync("01REC");
        Assert.Equal("/v1/signature-preservation/01REC", calls[0].Uri);
        Assert.Equal("ready", rec.EvidenceRecordStatus);
        Assert.Equal("https://x/evidence-record.ers", rec.EvidenceRecordUrl);

        var noSigs = Record.Replace(""","signatures":[{"index":0,"format":"CAdES","indication":"TOTAL_PASSED"}]""", "");
        var (client2, calls2) = Json(HttpStatusCode.OK, "{\"records\":[" + noSigs + "]}");
        var recs = await client2.ListSignaturePreservationsAsync(10);
        Assert.Equal("/v1/signature-preservation?limit=10", calls2[0].Uri);
        Assert.Single(recs);
        Assert.Null(recs[0].Signatures);
    }

    [Fact]
    public async Task NotFoundAlsoForTheBinaryDownloads()
    {
        var (client, _) = Json(HttpStatusCode.NotFound, """{"error":{"code":"NOT_FOUND","message":"Record not found."}}""");
        await Assert.ThrowsAsync<NotFoundException>(() => client.GetSignaturePreservationAsync("nope"));
        await Assert.ThrowsAsync<NotFoundException>(() => client.DownloadSignaturePreservationPackageAsync("nope"));
        await Assert.ThrowsAsync<NotFoundException>(() => client.VerifySignaturePreservationPdfAsync("nope", Submission));
    }

    [Fact]
    public async Task ThePackageIsTheZipBytes()
    {
        var zip = new byte[] { 0x50, 0x4b, 3, 4, 1 };
        var (client, calls) = Client(HttpStatusCode.OK, "application/zip", zip);
        Assert.Equal(zip, await client.DownloadSignaturePreservationPackageAsync("01REC"));
        Assert.Equal("/v1/signature-preservation/01REC/package", calls[0].Uri);
    }

    [Fact]
    public async Task VerifyReturnsTheReport()
    {
        var (client, calls) = Json(HttpStatusCode.OK, Report);
        var rep = await client.VerifySignaturePreservationAsync("01REC", Submission);
        Assert.Equal("/v1/signature-preservation/01REC/verify", calls[0].Uri);
        Assert.Equal(Submission, calls[0].Body);
        Assert.Equal("failed", rep.Result);
        Assert.Equal("file", rep.Steps[0].Name);
        Assert.Equal(new[] { "extractor" }, rep.Steps[0].CheckedBy);
        Assert.True(rep.Raw.ContainsKey("report_version"));
    }

    [Fact]
    public async Task VerifyAsPdfPostsTheSubmissionAndReturnsThePdf()
    {
        var (client, calls) = Client(HttpStatusCode.OK, "application/pdf", Encoding.ASCII.GetBytes("%PDF-1.7"));
        var pdf = await client.VerifySignaturePreservationPdfAsync("01REC", Submission);
        Assert.Equal("POST", calls[0].Method);
        Assert.Equal("/v1/signature-preservation/01REC/verify?format=pdf", calls[0].Uri);
        Assert.Equal("application/json", calls[0].ContentType);
        Assert.Equal(Submission, calls[0].Body);
        Assert.Equal("%PDF-1.7", Encoding.ASCII.GetString(pdf));
    }

    [Fact]
    public async Task DeleteSendsTheConfirmationAndMapsTheResult()
    {
        var (client, calls) = Json(HttpStatusCode.OK, """{"id":"01REC","deleted_at":"2026-10-13T11:00:00Z","peo_sha256":"dd"}""");
        var d = await client.DeleteSignaturePreservationAsync("01REC", "01REC");
        Assert.Equal("DELETE", calls[0].Method);
        Assert.Equal("/v1/signature-preservation/01REC?confirm=01REC", calls[0].Uri);
        Assert.Equal(new SignaturePreservationDeletion("01REC", "2026-10-13T11:00:00Z", "dd"), d);
    }

    [Fact]
    public async Task DeleteWithAWrongConfirmationOrAnUnknownRecord()
    {
        var (client, _) = Json(HttpStatusCode.BadRequest, """{"error":{"code":"CONFIRMATION_REQUIRED","message":"Repeat the id"}}""");
        var e = await Assert.ThrowsAsync<TrustBeatException>(() => client.DeleteSignaturePreservationAsync("01REC", "01OTHER"));
        Assert.Equal(400, e.Status);
        Assert.Equal("CONFIRMATION_REQUIRED", e.Code);
        var (client2, _) = Json(HttpStatusCode.NotFound, """{"error":{"code":"NOT_FOUND","message":"Record not found."}}""");
        await Assert.ThrowsAsync<NotFoundException>(() => client2.DeleteSignaturePreservationAsync("nope", "nope"));
    }
}

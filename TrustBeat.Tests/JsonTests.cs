using TrustBeat.Internal;

namespace TrustBeat.Tests;

public class JsonTests
{
    [Fact]
    public void ParsesFlatObject()
    {
        var m = Json.ParseObject("""{"id":"track-1","status":"pending","overage":false}""");
        Assert.Equal("track-1", Json.Str(m, "id"));
        Assert.Equal("pending",  Json.Str(m, "status"));
        Assert.False(Json.Bool(m, "overage", true));
    }

    [Fact]
    public void ParsesNullField()
    {
        var m = Json.ParseObject("""{"client_ref":null}""");
        Assert.Null(Json.Str(m, "client_ref"));
    }

    [Fact]
    public void ParsesNestedArray()
    {
        var m     = Json.ParseObject("""{"accepted":[{"id":"t1"},{"id":"t2"}]}""");
        var items = Json.Array(m, "accepted").ToList();
        Assert.Equal(2, items.Count);
        Assert.Equal("t1", Json.Str(items[0], "id"));
        Assert.Equal("t2", Json.Str(items[1], "id"));
    }

    [Fact]
    public void ParsesIntField()
    {
        var m = Json.ParseObject("""{"leaf_index":3}""");
        Assert.Equal(3, Json.Int(m, "leaf_index"));
    }

    [Fact]
    public void ParsesEscapedString()
    {
        var m = Json.ParseObject("""{"msg":"hello\"world"}""");
        Assert.Equal("hello\"world", Json.Str(m, "msg"));
    }

    [Fact]
    public void BuildObjectOmitsNullValues()
    {
        var json = Json.BuildObject(("hash", "aabbcc"), ("client_ref", null));
        Assert.DoesNotContain("client_ref", json);
        Assert.Contains("\"hash\":\"aabbcc\"", json);
    }

    [Fact]
    public void BuildObjectRoundTrips()
    {
        var json = Json.BuildObject(("hash", "abc"), ("flag", true), ("count", 5L));
        var m    = Json.ParseObject(json);
        Assert.Equal("abc", Json.Str(m, "hash"));
        Assert.True(Json.Bool(m, "flag", false));
        Assert.Equal(5, Json.Int(m, "count"));
    }
}

namespace TrustBeat.Internal;

/// <summary>
/// Factory used only by tests to inject a custom HttpMessageHandler.
/// The assembly-level InternalsVisibleTo attribute makes this accessible from the test project.
/// </summary>
internal static class ApiClientFactory
{
    internal static ApiClient Create(string apiKey, string baseUrl,
                                     System.Net.Http.HttpMessageHandler handler)
        => new(apiKey, baseUrl, handler);
}

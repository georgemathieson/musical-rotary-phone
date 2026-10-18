using System.Net;
using Microsoft.AspNetCore.Components;

namespace NetworkMonitor.Client.Services;

/// <summary>Sends the browser to the sign-in page when an API call reports the session has expired.</summary>
public sealed class UnauthorizedRedirectHandler(NavigationManager navigation) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        HttpResponseMessage response = await base.SendAsync(request, ct);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
            navigation.NavigateTo("login", forceLoad: true);
        return response;
    }
}

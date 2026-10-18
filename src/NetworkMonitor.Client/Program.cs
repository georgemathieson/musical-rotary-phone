using BlazorState;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using NetworkMonitor.Client;
using NetworkMonitor.Client.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Same-origin requests carry the sign-in cookie automatically; a 401 means the session expired.
builder.Services.AddScoped(sp => new HttpClient(
    new UnauthorizedRedirectHandler(sp.GetRequiredService<NavigationManager>()) { InnerHandler = new HttpClientHandler() })
{
    BaseAddress = new Uri(builder.HostEnvironment.BaseAddress),
});

// Redux-style state management (Blazor-State / MediatR). The store, actions and reducers live
// in this assembly, so that is what MediatR scans for handlers.
builder.Services.AddBlazorState(options =>
{
    options.Assemblies = new[] { typeof(Program).Assembly };
    // State payloads include large hex dumps; skip the per-dispatch deep clone to stay fast.
    options.UseCloneStateBehavior = false;
});

await builder.Build().RunAsync();

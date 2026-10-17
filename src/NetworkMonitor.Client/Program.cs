using BlazorState;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using NetworkMonitor.Client;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

// Redux-style state management (Blazor-State / MediatR). The store, actions and reducers live
// in this assembly, so that is what MediatR scans for handlers.
builder.Services.AddBlazorState(options =>
{
    options.Assemblies = new[] { typeof(Program).Assembly };
    // State payloads include large hex dumps; skip the per-dispatch deep clone to stay fast.
    options.UseCloneStateBehavior = false;
});

await builder.Build().RunAsync();

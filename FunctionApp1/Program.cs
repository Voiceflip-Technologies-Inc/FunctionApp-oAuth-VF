// .NET 7 isolated worker
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
// using Microsoft.Extensions.Logging; 
var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureAppConfiguration(cfg => { cfg.AddEnvironmentVariables(); })
    .ConfigureServices(services =>
    {
        services.AddLogging();                 // recomendado
        services.AddHttpClient();
        services.AddSingleton<TenantRegistry>();
        services.AddSingleton<MultiTenantGateway>();   // <-- faltaba
    })
    .Build(); // Build the host
// Run the host
await host.RunAsync();
// Usando .NET 7 y Azure Functions SDK
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
// Usa el SDK de Azure Functions
var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureAppConfiguration(cfg =>
    {
        // Lee App Settings de Azure (Environment Variables)
        cfg.AddEnvironmentVariables();
    })
    .ConfigureServices(services =>
    {
        services.AddHttpClient();
        services.AddSingleton<TenantRegistry>(); // <- DI para multi-tenant
    })
    .Build();
// Inicia la aplicación
await host.RunAsync();
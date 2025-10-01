// Usando .NET 8 y Azure Functions Isolated Worker
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
// using Microsoft.Azure.Functions.Worker.Configuration;
var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureAppConfiguration(cfg =>
    {
        cfg.AddEnvironmentVariables();
    })
    .ConfigureServices(services =>
    {
        services.AddHttpClient();
        services.AddSingleton<TenantRegistry>();       // registry multi-tenant
        services.AddSingleton<MultiTenantGateway>();   // <— NECESARIO para inyectarlo en DiagFunctions
        // Telemetría de App Insights:
        services.AddApplicationInsightsTelemetryWorkerService();
    }) // Configura los servicios de la aplicación
    .Build(); // Construye el host de la aplicación de funciones
// Inicia la aplicación de funciones
await host.RunAsync(); // End of Program.cs
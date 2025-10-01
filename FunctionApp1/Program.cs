using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
// using Microsoft.Azure.Functions.Worker.Configuration; // <- necesario para .NET 5/6
var host = new HostBuilder()
    .ConfigureAppConfiguration((ctx, cfg) =>
    {
        cfg.AddEnvironmentVariables(); // para TENANTS, TENANT__* en App Settings
    })
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices(services =>
    {
        services.AddHttpClient();
        services.AddSingleton<TenantRegistry>(); // <- aquí se registra
    })
    .Build();
//  Inicia la aplicación
await host.RunAsync();
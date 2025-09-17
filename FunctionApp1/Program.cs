using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices(s => s.AddHttpClient())
    .Build();
await host.RunAsync();
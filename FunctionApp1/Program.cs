/** 
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
**/
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
// using Microsoft.Azure.Functions.Worker.Configuration;
var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices(s =>
    {
        s.AddHttpClient();
    })
    .Build();
await host.RunAsync();
//host.Run();
/**
namespace FunctionApp1
{
    internal class Program
    {
        //TODO logic here
    }
}
**/
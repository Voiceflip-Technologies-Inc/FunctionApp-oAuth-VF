// Description: Diagnostic functions for Azure Functions app.
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Linq;
using System.Text.Json;
// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860
// https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference?tabs=csharp
// https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook?tabs=csharp
// https://learn.microsoft.com/en-us/azure/azure-functions/functions-develop-vs?tabs=csharp#local-settings-file
// https://learn.microsoft.com/en-us/azure/azure-functions/functions-develop-local?tabs=v2%2Cwindows%2Cportal%2Ccmd#local-settings-file
// https://learn.microsoft.com/en-us/azure/azure-functions/functions-develop-vs?tabs=csharp#local-settings-file
/// <summary>
///  Diagnostic functions for Azure Functions app.
/// </summary>
public class DiagFunctions
{
    private readonly IConfiguration _cfg;
    private readonly MultiTenantGateway _mtg;
    private readonly ILogger _logger;
    // public DiagFunctions(IConfiguration cfg) { _cfg = cfg; }
    public DiagFunctions(IConfiguration cfg, ILoggerFactory lf, MultiTenantGateway mtg)
    {
        _cfg = cfg;
        _logger = lf.CreateLogger<DiagFunctions>();
        _mtg = mtg;
    }
    /// <summary>
    /// Simple ping function to check if the service is alive.
    /// </summary>
    /// <param name="req"></param>
    /// <returns></returns>
    [Function("Ping")]
    public HttpResponseData Ping([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "ping")] HttpRequestData req)
    {
        // Simple ping function to check if the service is alive.
        var res = req.CreateResponse(HttpStatusCode.OK);
        res.WriteString("pong");
        return res; // Return "pong" response.
    }
    /// <summary>
    /// Check if required environment variables are set.
    /// </summary>
    /// <param name="req"></param>
    /// <returns></returns>
    [Function("EnvCheck")]
    public async Task<HttpResponseData> EnvCheck(
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "envcheck")] HttpRequestData req)
    {
        // Check if required environment variables are set.
        var data = new
        {
            ZENDESK_BASE_URL = string.IsNullOrWhiteSpace(_cfg["ZENDESK_BASE_URL"]) ? "(null)" : _cfg["ZENDESK_BASE_URL"],
            ZENDESK_CLIENT_ID = string.IsNullOrWhiteSpace(_cfg["ZENDESK_CLIENT_ID"]) ? "(null)" : "(set)",
            ZENDESK_CLIENT_SECRET = string.IsNullOrWhiteSpace(_cfg["ZENDESK_CLIENT_SECRET"]) ? "(null)" : "(set)",
            REDIRECT_URI = string.IsNullOrWhiteSpace(_cfg["REDIRECT_URI"]) ? "(null)" : _cfg["REDIRECT_URI"],
            SCOPES = string.IsNullOrWhiteSpace(_cfg["SCOPES"]) ? "(null)" : _cfg["SCOPES"]
        };
        // Return JSON response with environment variable status.
        var res = req.CreateResponse(HttpStatusCode.OK);
        res.Headers.Add("Content-Type", "application/json");
        await res.WriteStringAsync(JsonSerializer.Serialize(data));
        return res;
    }
    /// <summary>
    /// Function to diagnose loaded tenants from environment variable and parsed registry.
    /// </summary>
    /// <param name="req"></param>
    /// <returns></returns>
    [Function("DiagTenants")]
    public async Task<HttpResponseData> DiagTenants(
    [HttpTrigger(AuthorizationLevel.Function, "get", Route = "diag/tenants")] HttpRequestData req)
    {
        var snapshot = _mtg.Snapshot(); // devuelve un enumerable con los tenants cargados
        // var res = req.CreateResponse(HttpStatusCode.OK);
        // Return JSON response with environment variable TENANTS and parsed registry snapshot.
        var payload = new
        {
            envTenants = _cfg["TENANTS"],     // cadena “doorify,triangle”, etc.
            loaded = _mtg.Snapshot()          // snapshot del registry ya parseado
        };
        // Return JSON response with environment variable status.
        // await res.WriteAsJsonAsync(payload);
        var res = req.CreateResponse(HttpStatusCode.OK);
        res.Headers.Add("Content-Type", "application/json; charset=utf-8");
        //var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        //await res.WriteStringAsync(json);
        await res.WriteStringAsync(JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        // Return response.
        return res;
    } // DiagTenants
}
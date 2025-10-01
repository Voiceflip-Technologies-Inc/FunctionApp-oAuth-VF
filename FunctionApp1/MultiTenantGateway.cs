// .NET 7, Azure Functions v4
using System.Net;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
/*
 * Configuración de un tenant
 */
public sealed record TenantConfig(
    string BaseUrl,
    string ClientId,
    string ClientSecret,
    string Scopes
);
/*
 * Registro de tenants
 */
public class TenantRegistry
{
    private readonly Dictionary<string, TenantConfig> _tenants = new(StringComparer.OrdinalIgnoreCase);
    public bool AppendJson { get; }
    // Lee configuración de tenants desde IConfiguration
    public TenantRegistry(IConfiguration cfg)
    {
        // TENANTS=doorify,triangle
        var list = (cfg["TENANTS"] ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var t in list)
        {
            var prefix = $"TENANT__{t}__";
            var baseUrl = cfg[$"{prefix}BASE_URL"];
            var clientId = cfg[$"{prefix}CLIENT_ID"];
            var clientSecret = cfg[$"{prefix}CLIENT_SECRET"];
            var scopes = cfg[$"{prefix}SCOPES"] ?? "read";
            if (!string.IsNullOrWhiteSpace(baseUrl))
            {
                _tenants[t] = new TenantConfig(baseUrl.TrimEnd('/'), clientId ?? "", clientSecret ?? "", scopes);
            }
        }
        // Opcional: HELP_CENTER_APPEND_JSON=true
        AppendJson = string.Equals(cfg["HELP_CENTER_APPEND_JSON"], "true", StringComparison.OrdinalIgnoreCase);
    }
    // Intenta obtener configuración de tenant
    public bool TryGet(string tenant, out TenantConfig cfg) => _tenants.TryGetValue(tenant, out cfg);
    public IEnumerable<string> Names => _tenants.Keys;
}
/*
 * Multi-tenant gateway for OAuth2 and Help Center API
 */
public class MultiTenantGateway
{
    private readonly ILogger _log;
    private readonly TenantRegistry _tenants;
    private static readonly HttpClient _http = new HttpClient(new HttpClientHandler
    {
        AllowAutoRedirect = false
    });
    /*
     * multi-tenant gateway 
     */
    public MultiTenantGateway(ILoggerFactory logger, TenantRegistry tenants)
    {
        _log = logger.CreateLogger<MultiTenantGateway>();
        _tenants = tenants;
    }
    // ---------- 1) TOKEN POR TENANT ----------
    [Function("ClientCredentialsTokenByTenant")]
    public async Task<HttpResponseData> ClientCredentialsTokenByTenant(
        [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = "ClientCredentialsToken/{tenant?}")]
        HttpRequestData req,
        string? tenant)
    { // Si no viene en ruta, busca en query, default "doorify"
        tenant ??= req.Url.Query.Contains("tenant=") ? HttpUtility.ParseQueryString(req.Url.Query)["tenant"] : "doorify";
        // Valida tenant
        if (!_tenants.TryGet(tenant, out var tcfg))
            return await Error(req, HttpStatusCode.BadRequest, $"Tenant inválido. Usa uno de: {string.Join(", ", _tenants.Names)}");
        // Construye URL
        var tokenUrl = $"{tcfg.BaseUrl}/oauth/tokens";
        // Construye body
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = tcfg.ClientId,
            ["client_secret"] = tcfg.ClientSecret
        };
        if (!string.IsNullOrWhiteSpace(tcfg.Scopes)) form["scope"] = tcfg.Scopes;
        // use FormUrlEncodedContent
        using var body = new FormUrlEncodedContent(form);
        var http = await _http.PostAsync(tokenUrl, body);
        var content = await http.Content.ReadAsStringAsync();
        // Copia respuesta
        var resp = req.CreateResponse(http.StatusCode);
        foreach (var h in http.Headers) resp.Headers.Add(h.Key, string.Join(",", h.Value));
        foreach (var h in http.Content.Headers) resp.Headers.Add(h.Key, string.Join(",", h.Value));
        await resp.WriteStringAsync(content);
        return resp;
    }
    // ---------- 2) PROXY GENÉRICO ----------
    [Function("TenantProxy")]
    public async Task<HttpResponseData> TenantProxy(
        [HttpTrigger(AuthorizationLevel.Function, "get","post","put","patch","delete","head","options",
            Route = "proxy/{tenant}/{*path}")]
        HttpRequestData req,
        string tenant,
        string path)
    { // Valida tenant
        if (!_tenants.TryGet(tenant, out var tcfg))
            return await Error(req, HttpStatusCode.BadRequest, $"Tenant inválido. Usa uno de: {string.Join(", ", _tenants.Names)}");
        // Construye target URL
        var target = BuildTargetUrl(tcfg.BaseUrl, path, req.Url.Query);
        // Construye HttpRequestMessage
        var outbound = await BuildOutboundMessage(req, target);
        // Si no viene Authorization, opcionalmente mete Bearer desde client_credentials
        if (!outbound.Headers.Contains("Authorization"))
        {
            // Quita si NO quieres “auto token”
            var token = await FetchToken(tcfg);
            if (!string.IsNullOrEmpty(token))
                outbound.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        }
        // Envía
        var http = await _http.SendAsync(outbound, HttpCompletionOption.ResponseHeadersRead);
        return await CopyBack(req, http);
    }
    // ---------- 3) ATAJOS HELP CENTER ----------
    [Function("HelpCenterArticles")]
    public Task<HttpResponseData> HelpCenterArticles(
        [HttpTrigger(AuthorizationLevel.Function, "get",
            Route = "hc/{tenant}/{locale}/articles")]
        HttpRequestData req, string tenant, string locale)
        => HelpCenterAny(req, tenant, $"{locale}/articles");
    /*
     * Soporta cualquier verbo HTTP
     */
    [Function("HelpCenterAny")]
    public async Task<HttpResponseData> HelpCenterAny(
        [HttpTrigger(AuthorizationLevel.Function, "get","post","put","patch","delete","head","options",
            Route = "hc/{tenant}/{*rest}")]
        HttpRequestData req,
        string tenant,
        string rest)
    { // rest puede ser: en-us/articles, en-us/sections/123/articles, etc.
        if (!_tenants.TryGet(tenant, out var tcfg))
            return await Error(req, HttpStatusCode.BadRequest, $"Tenant inválido. Usa uno de: {string.Join(", ", _tenants.Names)}");
        // Construye /api/v2/help_center/{rest}[.json]
        var basePath = $"/api/v2/help_center/{rest.TrimStart('/')}";
        if (_tenants.AppendJson && !basePath.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            basePath += ".json";
        // Target URL
        var target = BuildTargetUrl(tcfg.BaseUrl, basePath.TrimStart('/'), req.Url.Query);
        var outbound = await BuildOutboundMessage(req, target);
        // Auto token (opcional)
        if (!outbound.Headers.Contains("Authorization"))
        {
            var token = await FetchToken(tcfg);
            if (!string.IsNullOrEmpty(token))
                outbound.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        }
        // Envía
        var http = await _http.SendAsync(outbound, HttpCompletionOption.ResponseHeadersRead);
        return await CopyBack(req, http);
    }
    // ---------- Helpers ----------
    private static string BuildTargetUrl(string baseUrl, string path, string query)
    {
        var p = path.TrimStart('/');
        var q = string.IsNullOrEmpty(query) ? "" : query; // ya trae '?'
        return $"{baseUrl}/{p}{q}";
    }
    /*
     * Construye HttpRequestMessage a partir de HttpRequestData
     */
    private async Task<HttpResponseMessage> BuildOutboundMessage(HttpRequestData req, string target)
    {
        var msg = new HttpRequestMessage(new HttpMethod(req.Method), target);
        // Copiar headers (excepto los de Host)
        foreach (var (key, val) in req.Headers)
        {
            if (string.Equals(key, "Host", StringComparison.OrdinalIgnoreCase)) continue;
            // Evitar duplicados conflictivos
            if (!msg.Headers.TryAddWithoutValidation(key, val))
            {
                // Puede ser content header…
            }
        }
        // Body si aplica
        if (req.Body != null && req.Body.CanRead && req.Body.Length > 0 &&
            req.Method is not "GET" and not "HEAD")
        {
            var ms = new MemoryStream();
            await req.Body.CopyToAsync(ms);
            ms.Position = 0;
            // Content-Type del request original
            var contentType = req.Headers.FirstOrDefault(h => string.Equals(h.Key, "Content-Type", StringComparison.OrdinalIgnoreCase)).Value ?? "application/octet-stream";
            msg.Content = new StreamContent(ms);
            msg.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        }
        // returns message
        return msg;
    }
    /*
     * Pide token OAuth2 client_credentials 
     */
    private async Task<string?> FetchToken(TenantConfig tcfg)
    {
        try
        {
            var tokenUrl = $"{tcfg.BaseUrl}/oauth/tokens";
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = tcfg.ClientId,
                ["client_secret"] = tcfg.ClientSecret
            };
            if (!string.IsNullOrWhiteSpace(tcfg.Scopes)) form["scope"] = tcfg.Scopes;
            // use FormUrlEncodedContent
            using var body = new FormUrlEncodedContent(form);
            var res = await _http.PostAsync(tokenUrl, body);
            res.EnsureSuccessStatusCode();
            using var s = await res.Content.ReadAsStreamAsync();
            using var doc = await JsonDocument.ParseAsync(s);
            return doc.RootElement.TryGetProperty("access_token", out var tok) ? tok.GetString() : null;
        }
        catch
        {
            return null;
        }
    }
    /*
     * Copia respuesta HTTP de HttpClient a HttpResponseData
     */
    private async Task<HttpResponseData> CopyBack(HttpRequestData req, HttpResponseMessage http)
    {
        var resp = req.CreateResponse(http.StatusCode);
        foreach (var h in http.Headers) resp.Headers.Add(h.Key, string.Join(",", h.Value));
        foreach (var h in http.Content.Headers) resp.Headers.Add(h.Key, string.Join(",", h.Value));
        if (http.Content != null)
        {
            await using var stream = await http.Content.ReadAsStreamAsync();
            await stream.CopyToAsync(resp.Body);
        }
        return resp;
    }
    /*
     * Errror helper
     */
    private async Task<HttpResponseData> Error(HttpRequestData req, HttpStatusCode code, string msg)
    {
        var r = req.CreateResponse(code);
        r.Headers.Add("Content-Type", "application/json; charset=utf-8");
        await r.WriteStringAsync(JsonSerializer.Serialize(new { error = msg }));
        return r;
    }
}
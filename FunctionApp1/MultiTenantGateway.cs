// Multi-tenant gateway for MLS support portals.
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Linq;
using System.Text.Json;
/// <summary>
/// Tenancy configuration.
/// </summary>
public sealed class TenantConfig
{
    public required string Name { get; init; }
    public required string BaseUrl { get; init; }          // https://support.doorifymls.com / http://support.trianglemls.com
    public string? ClientId { get; init; }
    public string? ClientSecret { get; init; }
    public string? Scopes { get; init; }
    public string TokenEndpointRelative { get; init; } = "/oauth/tokens";
}
/// <summary>
/// Contiene la configuración de los tenants registrados.
/// </summary>
public sealed class TenantRegistry
{
    /// <summary>
    /// Diccionario de tenants por nombre.
    /// </summary>
    private readonly Dictionary<string, TenantConfig> _tenants;
    /// <summary>
    /// Registra los tenants leyendo la configuración.
    /// </summary>
    /// <param name="cfg"></param>
    public TenantRegistry(IConfiguration cfg)
    {
        _tenants = new(StringComparer.OrdinalIgnoreCase);
        // Leer TENANTS y luego TENANT__<name>__*
        var list = (cfg["TENANTS"] ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var name in list)
        {
            var prefix = $"TENANT__{name}__";
            var baseUrl = cfg[$"{prefix}BASE_URL"];
            if (string.IsNullOrWhiteSpace(baseUrl)) continue;
            // Registrar
            _tenants[name] = new TenantConfig
            {
                Name = name,
                BaseUrl = baseUrl.TrimEnd('/'),
                ClientId = cfg[$"{prefix}CLIENT_ID"],
                ClientSecret = cfg[$"{prefix}CLIENT_SECRET"],
                Scopes = cfg[$"{prefix}SCOPES"],
                TokenEndpointRelative = cfg[$"{prefix}TOKEN_PATH"] ?? "/oauth/tokens"
            };
        }
    }
    /// <summary>
    /// Trata de obtener la configuración de un tenant por nombre.
    /// </summary>
    /// <param name="tenant"></param>
    /// <param name="cfg"></param>
    /// <returns></returns>
    public bool TryGet(string? tenant, out TenantConfig cfg)
    {
        if (tenant != null && _tenants.TryGetValue(tenant, out cfg!)) return true;
        // primer tenant como “default” si no se especifica
        cfg = _tenants.Values.FirstOrDefault()!;
        return cfg is not null;
    }
    /// <summary>
    /// Todos los nombres de tenant registrados.
    /// </summary>
    /// <returns></returns>
    public IEnumerable<string> AllTenantNames() => _tenants.Keys;
}
/// <summary>
/// Servicio de gateway multi-tenant.
/// </summary>
public sealed class MultiTenantGateway
{
    private readonly IHttpClientFactory _http;
    private readonly TenantRegistry _tenants;
    private readonly ILogger _log;
    /// <summary>
    /// Initializes a new instance of the <see cref="MultiTenantGateway"/> class, which provides functionality for
    /// managing HTTP requests across multiple tenants.
    /// </summary>
    /// <param name="http">The <see cref="IHttpClientFactory"/> used to create HTTP clients for making requests.</param>
    /// <param name="tenants">The <see cref="TenantRegistry"/> that contains information about the registered tenants.</param>
    /// <param name="loggerFactory">The <see cref="ILoggerFactory"/> used to create loggers for logging operations.</param>
    public MultiTenantGateway(IHttpClientFactory http, TenantRegistry tenants, ILoggerFactory loggerFactory)
    {
        _http = http;
        _tenants = tenants;
        _log = loggerFactory.CreateLogger<MultiTenantGateway>();
    }
    // -------- utilidades --------
    /// <summary>
    /// Combina una baseUrl con una ruta relativa o absoluta.
    /// </summary>
    /// <param name="baseUrl"></param>
    /// <param name="relativeOrAbsolute"></param>
    /// <returns></returns>
    private static Uri CombineUri(string baseUrl, string relativeOrAbsolute)
    {
        if (Uri.TryCreate(relativeOrAbsolute, UriKind.Absolute, out var abs)) return abs;
        return new Uri(new Uri(baseUrl + "/"), relativeOrAbsolute.TrimStart('/'));
    }
    /// <summary>
    /// Toma un TenantConfig y solicita un access_token con client_credentials.
    /// </summary>
    /// <param name="t"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    private async Task<string?> GetAccessTokenAsync(TenantConfig t, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(t.ClientId) || string.IsNullOrWhiteSpace(t.ClientSecret))
            return null; // no hay credenciales -> no se inyecta token
        // Construir URL token
        var tokenUrl = CombineUri(t.BaseUrl, t.TokenEndpointRelative);
        // Form-URL-encoded body
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = t.ClientId!,
            ["client_secret"] = t.ClientSecret!
        };
        if (!string.IsNullOrWhiteSpace(t.Scopes))
            form["scope"] = t.Scopes!;
        // Enviar petición
        try
        {
            var client = _http.CreateClient();
            // Aceptamos JSON en la respuesta
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            // Enviar
            using var content = new FormUrlEncodedContent(form);
            using var res = await client.PostAsync(tokenUrl, content, ct);
            var body = await res.Content.ReadAsStringAsync(ct);
            // Analizar respuesta
            if (!res.IsSuccessStatusCode)
            {
                _log.LogWarning("Token error [{Status}] {Body} (url: {Url})", res.StatusCode, body, tokenUrl);
                return null;
            }
            // Extraer access_token
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("access_token", out var at) ? at.GetString() : null;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Token request failed ({Url})", tokenUrl);
            return null;
        }
    } // GetAccessTokenAsync
    /// Copia los headers de una respuesta HttpResponseMessage a HttpResponseData.
    /// <summary>
    /// Copia los headers de una respuesta HttpResponseMessage a HttpResponseData.
    /// </summary>
    /// <param name="from"></param>
    /// <param name="to"></param>
    private static void CopyResponseHeaders(HttpResponseMessage from, HttpResponseData to)
    {
        foreach (var h in from.Headers)
            to.Headers.TryAddWithoutValidation(h.Key, string.Join(",", h.Value));

        foreach (var h in from.Content.Headers)
            to.Headers.TryAddWithoutValidation(h.Key, string.Join(",", h.Value));
    }
    // Copia el contenido de un HttpContent a un Stream (res.Body)
    private static async Task CopyContentAsync(HttpContent content, Stream target, CancellationToken ct)
    {
        await content.CopyToAsync(target, ct);
        target.Position = 0;
    }
    // -------- endpoints --------
    /// <summary>
    /// Ping simple para comprobar que la función está viva.
    /// </summary>
    /// <param name="req"></param>
    /// <returns></returns>
    [Function("Ping2")]
    public HttpResponseData Ping2([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "ping2")] HttpRequestData req)
    {
        var res = req.CreateResponse(HttpStatusCode.OK);
        res.Headers.Add("Content-Type", "text/plain");
        res.WriteString("pong");
        return res;
    }
    /// <summary>
    /// Devuelve un access_token con client_credentials para el tenant indicado (o el primero si no se indica).
    /// GET/POST /api/ClientCredentialsToken/{tenant?}
    /// </summary>
    [Function("IssueTenantToken")] // nombre único
    public async Task<HttpResponseData> ClientCredentialsToken(
        [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = "ClientCredentialsToken/{tenant?}")]
        HttpRequestData req,
        string? tenant,
        CancellationToken ct)
    {
        if (!_tenants.TryGet(tenant, out var t) || string.IsNullOrWhiteSpace(t.BaseUrl))
        {
            var notFound = req.CreateResponse(HttpStatusCode.NotFound);
            await notFound.WriteStringAsync($"Unknown tenant '{tenant}'.");
            return notFound;
        }
        // Obtener token
        var token = await GetAccessTokenAsync(t, ct);
        var res = req.CreateResponse(token is null ? HttpStatusCode.BadRequest : HttpStatusCode.OK);
        res.Headers.Add("Content-Type", "application/json; charset=utf-8");
        await res.WriteStringAsync(token is null ? "{\"error\":\"token_error\"}" : $"{{\"access_token\":\"{token}\"}}");
        return res;
    }
    /// <summary>
    /// Atajo para Triangle Help Center: /api/hc/{tenant}/{locale}/articles  ->  /api/v2/help_center/{locale}/articles.json
    /// </summary>
    [Function("HelpCenterArticles")]
    public Task<HttpResponseData> HelpCenterArticles(
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "hc/{tenant}/{locale}/articles")]
        HttpRequestData req, string tenant, string locale, CancellationToken ct)
        => ProxyInternal(req, tenant, $"api/v2/help_center/{locale}/articles.json", ct);
    /// <summary>
    /// Proxy genérico: /api/proxy/{tenant}/{*path}
    /// Copia método, querystring y body. Si el cliente NO manda Authorization, se intenta inyectar Bearer con client_credentials.
    /// </summary>
    [Function("Proxy")]
    public Task<HttpResponseData> Proxy(
        [HttpTrigger(AuthorizationLevel.Function, "get", "post", "put", "patch", "delete", "head", "options",
            Route = "proxy/{tenant}/{*path}")]
        HttpRequestData req, string tenant, string path, CancellationToken ct)
        => ProxyInternal(req, tenant, path, ct);
    // -------- implementación del proxy --------
/*
 * Pasos:
 * - Validar tenant
 * - Construir URL destino
 * - Construir request saliente (método, URL, headers, body)
 * - Authorization
 */
private async Task<HttpResponseData> ProxyInternal(HttpRequestData req, string tenant, string path, CancellationToken ct)
{
    if (!_tenants.TryGet(tenant, out var t) || string.IsNullOrWhiteSpace(t.BaseUrl))
    {
        var nf = req.CreateResponse(HttpStatusCode.NotFound);
        await nf.WriteStringAsync($"Unknown tenant '{tenant}'.");
        return nf;
    }
    // Construir URL destino
    var targetUri = CombineUri(t.BaseUrl, $"{path}{req.Url.Query}");
    var method = new HttpMethod(req.Method);
    // Construir request saliente
    var outbound = new HttpRequestMessage(method, targetUri);
    // Body (sólo cuando aplica)
    if (req.Body is not null &&
        (method == HttpMethod.Post || method == HttpMethod.Put || method.Method.Equals("PATCH", StringComparison.OrdinalIgnoreCase)))
    {
        var ms = new MemoryStream();
        await req.Body.CopyToAsync(ms, ct);
        ms.Position = 0;
        outbound.Content = new StreamContent(ms);
        // Content-Type si viene
        if (req.Headers.TryGetValues("Content-Type", out var cts))
            outbound.Content.Headers.TryAddWithoutValidation("Content-Type", string.Join(",", cts));
    }
    // Copiar headers (excepto Host)
    foreach (var h in req.Headers)
    {
        if (h.Key.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
        // Intentar como header normal
        if (!outbound.Headers.TryAddWithoutValidation(h.Key, h.Value))
        {
            // Si no entra, y tenemos content, probar como header de contenido
            if (outbound.Content != null)
                outbound.Content.Headers.TryAddWithoutValidation(h.Key, h.Value);
        }
    }
    // Authorization: si el cliente no lo envía, inyectamos uno si podemos
    var hasAuth = req.Headers.TryGetValues("Authorization", out var authVals) && authVals.Any(v => !string.IsNullOrWhiteSpace(v));
    if (!hasAuth)
    {
        var token = await GetAccessTokenAsync(t, ct);
        if (!string.IsNullOrWhiteSpace(token))
            outbound.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    } // else: se respeta el Authorization que venga
        try // enviar
        {
            var client = _http.CreateClient();
            using var upstream = await client.SendAsync(outbound, HttpCompletionOption.ResponseHeadersRead, ct);

            var res = req.CreateResponse((HttpStatusCode)upstream.StatusCode);
            CopyResponseHeaders(upstream, res);
            await CopyContentAsync(upstream.Content, res.Body, ct);
            return res;
        }
        catch (HttpRequestException ex)
        {
            _log.LogError(ex, "Upstream request failed: {Method} {Uri}", outbound.Method, outbound.RequestUri);
            var res = req.CreateResponse(HttpStatusCode.BadGateway);
            res.Headers.Add("Content-Type", "application/json; charset=utf-8");
            await res.WriteStringAsync("{\"error\":\"bad_gateway\",\"detail\":\"upstream unreachable\"}");
            return res;
        } // catch
    } // ProxyInternal
    /// <summary>
    /// snapshot de la configuración de tenants (para diagnóstico)
    /// </summary>
    /// <returns></returns>
    public IEnumerable<object> Snapshot()
    {
        // Recorremos los nombres registrados y pedimos cada config
        return _tenants.AllTenantNames().Select(name =>
        {
            // Siempre existe si está en AllTenantNames
            _tenants.TryGet(name, out var t); // seguro porque viene de AllTenantNames()
            // construir tokenUrl
            var tokenPath = t.TokenEndpointRelative ?? "/oauth/tokens";
            //var tokenUrl = CombineUri(t.BaseUrl, tokenPath).ToString();
            var tokenUrl = CombineUri(t.BaseUrl, t.TokenEndpointRelative).ToString();
            // devolver info menos sensible
            return new
            {
                name,
                baseUrl = t.BaseUrl,
                tokenPath = t.TokenEndpointRelative,
                tokenUrl,
                clientId = t.ClientId,
                hasClientSecret = !string.IsNullOrEmpty(t.ClientSecret),
                scopes = t.Scopes
            }; // return new object
        }); // select
    } // Snapshot
} // class
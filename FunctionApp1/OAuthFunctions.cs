// Libraries
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
/// <summary>
/// Funciones para manejar OAuth con Zendesk
/// </summary>
public class OAuthFunctions
{
    // Dependencies
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger _log;
    private readonly IConfiguration _cfg;
    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="httpClientFactory"></param>
    /// <param name="loggerFactory"></param>
    /// <param name="cfg"></param>
    public OAuthFunctions(IHttpClientFactory httpClientFactory, ILoggerFactory loggerFactory, IConfiguration cfg)
    {
        // Guard clauses     
        _httpClientFactory = httpClientFactory;
        _log = loggerFactory.CreateLogger<OAuthFunctions>();
        _cfg = cfg;
    }
    /// <summary>
    /// Valida settings y devuelve versiones seguras (sin nulls)
    /// </summary>
    /// <returns></returns>    
    private (bool ok, string? msg, string baseUrl, string clientId, string clientSecret, string redirectUri, string scopes)
        Validate() // 7-tuple
    {
        var baseUrl = _cfg["ZENDESK_BASE_URL"] ?? "";
        var clientId = _cfg["ZENDESK_CLIENT_ID"] ?? "";
        var clientSecret = _cfg["ZENDESK_CLIENT_SECRET"] ?? "";
        var redirectUri = _cfg["REDIRECT_URI"] ?? "";
        var scopes = _cfg["SCOPES"] ?? "read write";
        // Check required
        var missing = new List<string>();
        if (string.IsNullOrWhiteSpace(baseUrl)) missing.Add("ZENDESK_BASE_URL");
        if (string.IsNullOrWhiteSpace(clientId)) missing.Add("ZENDESK_CLIENT_ID");
        if (string.IsNullOrWhiteSpace(clientSecret)) missing.Add("ZENDESK_CLIENT_SECRET");
        if (string.IsNullOrWhiteSpace(redirectUri)) missing.Add("REDIRECT_URI");
        // Scopes can be empty, default to "read write"
        if (missing.Count > 0)
            return (false, "Missing settings: " + string.Join(", ", missing), "", "", "", "", "");
        //  All good
        return (true, null, baseUrl.TrimEnd('/'), clientId, clientSecret, redirectUri, scopes);
    }
    /// <summary>
    /// Utilidad para leer querystring sin System.Web
    /// </summary>
    /// <returns></returns>   
    private static string? Q(string query, string key)
    {
        // Simple cases
        if (string.IsNullOrEmpty(query)) return null;
        foreach (var kv in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            // Split on first '='
            var i = kv.IndexOf('=');
            var k = WebUtility.UrlDecode(i < 0 ? kv : kv[..i]);
            if (!string.Equals(k, key, StringComparison.OrdinalIgnoreCase)) continue;
            return i < 0 ? "" : WebUtility.UrlDecode(kv[(i + 1)..]);
        }
        return null; // Not found
    }
    /// <summary>
    /// Inicia el flujo de autorización redirigiendo a la URL de Zendesk
    /// </summary>
    /// <param name="req"></param>
    /// <returns></returns>
    [Function("StartAuth")]
    public async Task<HttpResponseData> StartAuthAsync(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oauth/start")] HttpRequestData req)
    {
        var (ok, msg, baseUrl, clientId, _, redirectUri, scopes) = Validate();
        if (!ok)
        {
            var bad = req.CreateResponse(HttpStatusCode.InternalServerError);
            await bad.WriteStringAsync(msg!);
            return bad;
        }
        // Generate a random state value
        var state = Convert.ToBase64String(Guid.NewGuid().ToByteArray())
                        .Replace("+", "").Replace("/", "").Replace("=", "");
        // Build the authorization URL
        var authUrl = $"{baseUrl}/oauth/authorizations/new" +
                      $"?response_type=code&client_id={Uri.EscapeDataString(clientId)}" +
                      $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                      $"&scope={Uri.EscapeDataString(scopes)}" +
                      $"&state={Uri.EscapeDataString(state)}";
        // Redirect with state in a cookie
        var res = req.CreateResponse(HttpStatusCode.Redirect);
        res.Headers.Add("Set-Cookie", $"vf_state={state}; HttpOnly; Secure; SameSite=Lax; Path=/");
        res.Headers.Add("Location", authUrl);
        return res;
    }
    /// <summary>
    /// Callback que recibe el código de autorización, valida state y pide el token
    /// </summary>
    /// <param name="req"></param>
    /// <returns></returns>
    [Function("OAuthCallback")]
    public async Task<HttpResponseData> OAuthCallback(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oauth/callback")] HttpRequestData req)
    {
        var (ok, msg, baseUrl, clientId, clientSecret, redirectUri, _) = Validate();
        if (!ok)
        {
            var bad = req.CreateResponse(HttpStatusCode.InternalServerError);
            await bad.WriteStringAsync(msg!);
            return bad;
        }
        //  Read code and state from querystring
        var code = Q(req.Url.Query, "code");
        var state = Q(req.Url.Query, "state");
        //  Read state from cookie
        var cookieHeader = req.Headers.TryGetValues("Cookie", out var cookies) ? string.Join(";", cookies) : "";
        var stateCookie = cookieHeader.Split(';').FirstOrDefault(c => c.TrimStart().StartsWith("vf_state="))?.Split('=')?.LastOrDefault();
        //  Validate state and code
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state) || stateCookie != state)
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("Invalid OAuth state or missing code.");
            return bad;
        }
        //  Prepare form data
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["redirect_uri"] = redirectUri
        };
        //  Call the token endpoint
        var http = _httpClientFactory.CreateClient();
        var tokenEndpoint = $"{baseUrl}/oauth/tokens";
        var resp = await http.PostAsync(tokenEndpoint, new FormUrlEncodedContent(form));
        var json = await resp.Content.ReadAsStringAsync();
        // Prepare response
        var res = req.CreateResponse(resp.IsSuccessStatusCode ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
        res.Headers.Add("Content-Type", "text/html; charset=utf-8");
        // Show a friendly message with the token (masked) or the error
        try
        {
            var doc = JsonDocument.Parse(json);
            var access = doc.RootElement.TryGetProperty("access_token", out var t) ? t.GetString() ?? "" : "";
            var masked = access.Length > 8 ? $"{access[..4]}•••{access[^4..]}" : "received";
            await res.WriteStringAsync($"<h3>OAuth listo ✅</h3><p>Access token: <b>{masked}</b></p>");
        }
        catch
        {
            await res.WriteStringAsync($"<pre>{WebUtility.HtmlEncode(json)}</pre>");
        }
        return res; //  OK
    }
    /// <summary>
    /// 
    /// </summary>
    /// <param name="req"></param>
    /// <returns></returns>
    [Function("LegacyClientCredentialsToken")]
    public async Task<HttpResponseData> LegacyClientCredentialsToken(
        [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = "oauth/token/client")] HttpRequestData req)
    {
        var (ok, msg, baseUrl, clientId, clientSecret, _, _) = Validate();
        if (!ok)
        {
            var bad = req.CreateResponse(HttpStatusCode.InternalServerError);
            await bad.WriteStringAsync(msg!);
            return bad;
        }
        // Prepare form data
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        };
        // Call the token endpoint
        var http = _httpClientFactory.CreateClient();
        var resp = await http.PostAsync($"{baseUrl}/oauth/tokens", new FormUrlEncodedContent(form));
        // Just relay the response
        var outRes = req.CreateResponse(resp.IsSuccessStatusCode ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
        await outRes.WriteStringAsync(await resp.Content.ReadAsStringAsync());
        return outRes;
    }
    /// <summary>
    /// Testea un token de acceso (pasado en ?token=) llamando al endpoint "current token"
    /// </summary>
    /// <param name="req"></param>
    /// <returns></returns>
    [Function("TestToken")]
    public async Task<HttpResponseData> TestToken(
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "oauth/test")] HttpRequestData req)
    {
        var (ok, msg, baseUrl, _, _, _, _) = Validate();
        if (!ok)
        {
            var bad = req.CreateResponse(HttpStatusCode.InternalServerError);
            await bad.WriteStringAsync(msg!);
            return bad;
        }
        // Read token from ?token= querystring
        var token = Q(req.Url.Query, "token");
        if (string.IsNullOrWhiteSpace(token))
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("Pass ?token=YOUR_ACCESS_TOKEN");
            return bad;
        }
        // Call the "current token" endpoint
        var http = _httpClientFactory.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var resp = await http.GetAsync($"{baseUrl}/api/v2/oauth/tokens/current.json");
        // Just relay the response
        var outRes = req.CreateResponse(resp.IsSuccessStatusCode ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
        await outRes.WriteStringAsync(await resp.Content.ReadAsStringAsync());
        return outRes;
    }
}
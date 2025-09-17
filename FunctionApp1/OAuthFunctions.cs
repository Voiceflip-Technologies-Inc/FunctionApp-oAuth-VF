using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Azure.WebJobs;
//using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace FunctionApp1
{
    public class OAuthFunctions
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger _log;
        private readonly IConfiguration _cfg;

        public OAuthFunctions(IHttpClientFactory httpClientFactory, ILoggerFactory loggerFactory, IConfiguration cfg)
        {
            _httpClientFactory = httpClientFactory;
            _log = loggerFactory.CreateLogger<OAuthFunctions>();
            _cfg = cfg;
        }

        private string BaseUrl => _cfg["ZENDESK_BASE_URL"]!.TrimEnd('/');
        private string ClientId => _cfg["ZENDESK_CLIENT_ID"]!;
        private string ClientSecret => _cfg["ZENDESK_CLIENT_SECRET"]!;
        private string RedirectUri => _cfg["REDIRECT_URI"]!;
        private string Scopes => _cfg["SCOPES"] ?? "read write";

        // Utilidad para parsear el query sin System.Web
        private static string? Q(string query, string key)
        {
            if (string.IsNullOrEmpty(query)) return null;
            foreach (var kv in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var i = kv.IndexOf('=');
                var k = WebUtility.UrlDecode(i < 0 ? kv : kv[..i]);
                if (!string.Equals(k, key, StringComparison.OrdinalIgnoreCase)) continue;
                return i < 0 ? "" : WebUtility.UrlDecode(kv[(i + 1)..]);
            }
            return null;
        }

        // 1) Inicio del flujo Authorization Code
        [Function("StartAuth")]
        public HttpResponseData StartAuth([Microsoft.Azure.Functions.Worker.HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oauth/start")] HttpRequestData req)
        {
            // Genera un state y lo guarda en cookie (simple demo anti-CSRF).
            var state = Convert.ToBase64String(Guid.NewGuid().ToByteArray())
                .Replace("+", "").Replace("/", "").Replace("=", "");

            var authUrl = $"{BaseUrl}/oauth/authorizations/new" +
                          $"?response_type=code&client_id={Uri.EscapeDataString(ClientId)}" +
                          $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}" +
                          $"&scope={Uri.EscapeDataString(Scopes)}" +
                          $"&state={Uri.EscapeDataString(state)}";

            var res = req.CreateResponse(HttpStatusCode.Redirect);
            res.Headers.Add("Set-Cookie", $"vf_state={state}; HttpOnly; Secure; SameSite=Lax; Path=/");
            res.Headers.Add("Location", authUrl);
            return res;
        }

        // 2) Callback: canjea "code" por tokens
        [Function("OAuthCallback")]
        public async Task<HttpResponseData> OAuthCallback([Microsoft.Azure.Functions.Worker.HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oauth/callback")] HttpRequestData req)
        {
            var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
            var code = query["code"];
            var state = query["state"];
            var cookie = req.Headers.TryGetValues("Cookie", out var cookieVals) ? string.Join(";", cookieVals) : "";
            var stateCookie = cookie.Split(';').FirstOrDefault(c => c.TrimStart().StartsWith("vf_state="))?.Split('=')?.LastOrDefault();

            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state) || stateCookie != state)
            {
                var bad = req.CreateResponse(HttpStatusCode.BadRequest);
                await bad.WriteStringAsync("Invalid OAuth state or missing code.");
                return bad;
            }

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code!,
                ["client_id"] = ClientId,
                ["client_secret"] = ClientSecret,
                ["redirect_uri"] = RedirectUri
            };

            var http = _httpClientFactory.CreateClient();
            var tokenEndpoint = $"{BaseUrl}/oauth/tokens";
            var resp = await http.PostAsync(tokenEndpoint, new FormUrlEncodedContent(form));
            var json = await resp.Content.ReadAsStringAsync();

            _log.LogInformation("Token exchange status: {Status} body length: {Len}", resp.StatusCode, json.Length);

            var ok = req.CreateResponse(resp.IsSuccessStatusCode ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
            ok.Headers.Add("Content-Type", "text/html; charset=utf-8");

            // No mostramos el token completo en HTML por seguridad
            try
            {
                var doc = JsonDocument.Parse(json);
                var access = doc.RootElement.GetProperty("access_token").GetString() ?? "";
                var masked = access.Length > 8 ? $"{access[..4]}•••{access[^4..]}" : "received";
                await ok.WriteStringAsync($@"<h3>OAuth Ready ✅</h3>
                <p>We obtain an access_token (masked): <b>{masked}</b></p>
                <p>Save it on the Key Vault or use it from the backend to call the API of ZenDesk.</p>");
            }
            catch
            {
                await ok.WriteStringAsync($"<pre>{WebUtility.HtmlEncode(json)}</pre>");
            }
            return ok;
        }

        // 3) Flujo rápido: Client Credentials (sin navegador)
        [Function("ClientCredentialsToken")]
        public async Task<HttpResponseData> ClientCredentialsToken([Microsoft.Azure.Functions.Worker.HttpTrigger(AuthorizationLevel.Function, "post", "get", Route = "oauth/token/client")] HttpRequestData req)
        {
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = ClientId,
                ["client_secret"] = ClientSecret
            };
            var http = _httpClientFactory.CreateClient();
            var resp = await http.PostAsync($"{BaseUrl}/oauth/tokens", new FormUrlEncodedContent(form));
            var outRes = req.CreateResponse(resp.IsSuccessStatusCode ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
            var body = await resp.Content.ReadAsStringAsync();
            await outRes.WriteStringAsync(body);
            return outRes;
        }

        // 4) Prueba de token contra Zendesk
        [Function("TestToken")]
        public async Task<HttpResponseData> TestToken([Microsoft.Azure.Functions.Worker.HttpTrigger(AuthorizationLevel.Function, "get", Route = "oauth/test")] HttpRequestData req)
        {
            var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
            var token = query["token"];
            if (string.IsNullOrEmpty(token))
            {
                var bad = req.CreateResponse(HttpStatusCode.BadRequest);
                await bad.WriteStringAsync("Pass ?token=YOUR_ACCESS_TOKEN");
                return bad;
            }
            var http = _httpClientFactory.CreateClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var resp = await http.GetAsync($"{BaseUrl}/api/v2/oauth/tokens/current.json");
            var outRes = req.CreateResponse(resp.IsSuccessStatusCode ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
            await outRes.WriteStringAsync(await resp.Content.ReadAsStringAsync());
            return outRes;
        }
    }
}
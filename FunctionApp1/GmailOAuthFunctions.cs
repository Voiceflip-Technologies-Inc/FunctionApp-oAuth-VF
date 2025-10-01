/// Proyecto: FunctionApp1
using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
/// <summary>
/// Funciones para OAuth2 con Google/Gmail y envío de correo
/// </summary>
public class GmailOAuthFunctions
{
    /// <summary>
    /// HttpClient estático para reutilizar conexiones (mejor rendimiento)
    /// </summary>
    private static readonly HttpClient Http = new HttpClient();
    /// <summary>
    /// Lee una variable de entorno o devuelve cadena vacía
    /// </summary>
    /// <param name="name"></param>
    /// <returns></returns>
    private static string Env(string name) =>
        Environment.GetEnvironmentVariable(name) ?? string.Empty;
    /// <summary>
    /// Encodea en Base64 URL Safe (sin padding, +/= reemplazados)
    /// </summary>
    /// <param name="input"></param>
    /// <returns></returns>
    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    /// <summary>
    /// Encodea un valor para usar en URL (query string)
    /// </summary>
    /// <param name="v"></param>
    /// <returns></returns>
    private static string UrlEncode(string v) => Uri.EscapeDataString(v);
    /// <summary>
    /// Construye una query string a partir de pares clave/valor
    /// </summary>
    /// <param name="pairs"></param>
    /// <returns></returns>
    private static string BuildQuery((string k, string v)[] pairs)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < pairs.Length; i++)
        {
            if (i > 0) sb.Append('&');
            sb.Append(UrlEncode(pairs[i].k)).Append('=').Append(UrlEncode(pairs[i].v));
        }
        return sb.ToString();
    }
    // GET /api/oauth/gcloud/start   (Anonymous)
    [Function("GmailStart")]
    public HttpResponseData GmailStart(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oauth/gcloud/start")]
        HttpRequestData req)
    {
        var clientId = Env("GOOGLE_CLIENT_ID");
        var redirect = Env("GOOGLE_REDIRECT_URI");
        var scopes = Env("GMAIL_SCOPES");
        if (string.IsNullOrEmpty(scopes))
            scopes = "openid email profile https://www.googleapis.com/auth/gmail.send";
        // En producción guarda/verifica 'state' (p.ej. en Table Storage) para antifraude CSRF
        var state = Guid.NewGuid().ToString("n");
        // Construimos la query string
        var q = BuildQuery(new[]
        {
            ("client_id", clientId),
            ("redirect_uri", redirect),
            ("response_type", "code"),
            ("scope", scopes),
            ("access_type", "offline"),                 // <-- refresh_token
            ("include_granted_scopes", "true"),
            ("prompt", "consent"),                      // <-- fuerza refresh_token la 1ª vez
            ("state", state)
        });
        // Redirigimos al endpoint de OAuth de Google
        var url = $"https://accounts.google.com/o/oauth2/v2/auth?{q}";
        var res = req.CreateResponse(HttpStatusCode.Redirect);
        res.Headers.Add("Location", url);
        return res;
    }
    // GET /api/oauth/gcloud/callback  (Anonymous)  -> Intercambia code por tokens
    [Function("GmailCallback")]
    public async Task<HttpResponseData> GmailCallback(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oauth/gcloud/callback")]
        HttpRequestData req)
    {
        var uri = req.Url;
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query); // ok en isolated con System.Web.HttpUtility
        var code = query["code"];
        var error = query["error"];
        if (!string.IsNullOrEmpty(error) || string.IsNullOrEmpty(code))
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync($"OAuth error: {error ?? "missing code"}");
            return bad;
        }
        // Credenciales de la app
        var clientId = Env("GOOGLE_CLIENT_ID");
        var clientSecret = Env("GOOGLE_CLIENT_SECRET");
        var redirect = Env("GOOGLE_REDIRECT_URI");
        // Construimos el body para el POST
        var form = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string,string>("code", code),
            new KeyValuePair<string,string>("client_id", clientId),
            new KeyValuePair<string,string>("client_secret", clientSecret),
            new KeyValuePair<string,string>("redirect_uri", redirect),
            new KeyValuePair<string,string>("grant_type", "authorization_code"),
        });
        // Intercambiamos code por tokens
        var tokenResp = await Http.PostAsync("https://oauth2.googleapis.com/token", form);
        var body = await tokenResp.Content.ReadAsStringAsync();
        // body contiene { access_token, refresh_token, expires_in, token_type, scope }
        var ok = req.CreateResponse(tokenResp.IsSuccessStatusCode ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
        ok.Headers.Add("Content-Type", "application/json; charset=utf-8");
        await ok.WriteStringAsync(body);
        // Sugerido: aquí podrías persisitir 'refresh_token' en Key Vault.
        // var token = JsonSerializer.Deserialize<TokenResponse>(body);
        // await SaveRefreshTokenAsync(token.refresh_token);
        return ok;
    }
    // GET /api/gmail/access-token   (Function) -> devuelve access_token desde refresh_token
    //   - Usa Function Key (?code=...) para protegerlo
    [Function("GmailAccessToken")]
    public async Task<HttpResponseData> GmailAccessToken(
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "gmail/access-token")]
        HttpRequestData req)
    {
        // Opciones para obtener el refresh token:
        // 1) de App Setting GMAIL_REFRESH_TOKEN (copiado manualmente tras la primera auth)
        // 2) de Key Vault (recomendado) [no implementado aquí por brevedad]
        var refresh = Environment.GetEnvironmentVariable("GMAIL_REFRESH_TOKEN");
        if (string.IsNullOrWhiteSpace(refresh))
        {
            var bad = req.CreateResponse(HttpStatusCode.PreconditionFailed);
            await bad.WriteStringAsync("Configura GMAIL_REFRESH_TOKEN en app settings (o implementa Key Vault).");
            return bad;
        }
        // Credenciales de la app
        var clientId = Env("GOOGLE_CLIENT_ID");
        var clientSecret = Env("GOOGLE_CLIENT_SECRET");
        // Construimos el body para el POST
        var form = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string,string>("client_id", clientId),
            new KeyValuePair<string,string>("client_secret", clientSecret),
            new KeyValuePair<string,string>("refresh_token", refresh),
            new KeyValuePair<string,string>("grant_type", "refresh_token"),
        });
        // Intercambiamos refresh_token por access_token
        var tokenResp = await Http.PostAsync("https://oauth2.googleapis.com/token", form);
        var body = await tokenResp.Content.ReadAsStringAsync();
        // body contiene { access_token, expires_in, scope, token_type }
        var res = req.CreateResponse(tokenResp.IsSuccessStatusCode ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
        res.Headers.Add("Content-Type", "application/json; charset=utf-8");
        await res.WriteStringAsync(body);
        return res;
    }
    // POST /api/gmail/send  (Function) -> envía un correo con el access_token vigente
    // Body JSON: { "to":"dest@dom.com", "subject":"...", "text":"..." }
    [Function("GmailSend")]
    public async Task<HttpResponseData> GmailSend(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = "gmail/send")]
        HttpRequestData req)
    {
        var payload = await JsonSerializer.DeserializeAsync<SendEmailDto>(req.Body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (payload == null || string.IsNullOrWhiteSpace(payload.To))
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("JSON inválido. Esperado: { to, subject, text }");
            return bad;
        }
        // Pedimos un access_token al propio endpoint interno (reutilizamos lógica)
        var key = req.Headers.TryGetValues("x-functions-key", out var vals) ? System.Linq.Enumerable.FirstOrDefault(vals) : null;
        var self = $"{req.Url.Scheme}://{req.Url.Host}{(req.Url.IsDefaultPort ? "" : ":" + req.Url.Port)}/api/gmail/access-token";
        if (!string.IsNullOrEmpty(req.FunctionContext.Invocation.FunctionId)) { /* NOOP solo para content */ }
        // Construimos la URL con la Function Key (si existe)
        var msg = new HttpRequestMessage(HttpMethod.Get, self + (string.IsNullOrEmpty(key) ? "" : $"?code={UrlEncode(key)}"));
        var tokenCall = await Http.SendAsync(msg);
        if (!tokenCall.IsSuccessStatusCode)
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("No se pudo obtener access_token.");
            return bad;
        }
        // Extraemos access_token del JSON
        var tokenJson = await tokenCall.Content.ReadAsStringAsync();
        var token = JsonSerializer.Deserialize<TokenResponse>(tokenJson);
        if (token == null || string.IsNullOrEmpty(token.access_token))
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("Respuesta de token inválida.");
            return bad;
        }
        // Ya tenemos access_token, preparamos y enviamos el correo
        var rawMime = $"To: {payload.To}\r\nSubject: {payload.Subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{payload.Text}";
        var raw64 = Base64UrlEncode(Encoding.UTF8.GetBytes(rawMime));
        // Alternativamente, usar MimeKit para crear el MIME (más completo)
        var sendReq = new HttpRequestMessage(HttpMethod.Post, "https://gmail.googleapis.com/gmail/v1/users/me/messages/send");
        sendReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token.access_token);
        sendReq.Content = new StringContent(JsonSerializer.Serialize(new { raw = raw64 }), Encoding.UTF8, "application/json");
        // Alternativamente, usar MimeKit para crear el MIME (más completo)
        var sendResp = await Http.SendAsync(sendReq);
        var body = await sendResp.Content.ReadAsStringAsync();
        // body contiene info del mensaje enviado (id, threadId...)
        var res = req.CreateResponse(sendResp.IsSuccessStatusCode ? HttpStatusCode.OK : HttpStatusCode.BadRequest);
        res.Headers.Add("Content-Type", "application/json; charset=utf-8");
        await res.WriteStringAsync(body);
        return res;
    }
    /// <summary>
    /// Tipo para deserializar respuesta de token
    /// </summary>
    /// <param name="access_token"></param>
    /// <param name="refresh_token"></param>
    /// <param name="expires_in"></param>
    /// <param name="token_type"></param>
    /// <param name="scope"></param>
    private record TokenResponse(string access_token, string refresh_token, int expires_in, string token_type, string scope);
    /// <summary>
    /// Estructura del body JSON para enviar correo
    /// </summary>
    /// <param name="To"></param>
    /// <param name="Subject"></param>
    /// <param name="Text"></param>
    private record SendEmailDto(string To, string Subject, string Text);
}
# VoiceFlip Authentication (Azure Functions – Zendesk OAuth)

Minimal authentication framework for integrating with Zendesk using Azure Functions .NET 8 Isolated. Exposed endpoints for:
- Authorization code flow (interactive) with /api/oauth/start → /api/oauth/callback.
- Client credentials flow (machine-to-machine) with /api/oauth/token/client.
- Token verification with /api/oauth/test.

The functions are implemented in OAuthFunctions.cs using Microsoft.Azure.Functions.Worker + Worker.Extensions.Http.
The host startup is in Program.cs with top-level declarations.
The HTTP/host configuration is in host.json.

## Endpoints

- `GET /api/oauth/start`
Redirect to Zendesk (`/oauth/authorizations/new`) with `client_id`, `redirect_uri`, `scope` and `state`.

- `GET /api/oauth/callback?code=...&state=...`
Exchange `code` for `access_token` in `POST /oauth/tokens`. Displays the **masked** token in HTML.

- `GET|POST /api/oauth/token/client` _(AuthorizationLevel.Function)_
Request an **access_token** via `client_credentials` (`POST /oauth/tokens`). Requires `?code=<FUNCTION_KEY>`.

- `GET /api/oauth/test?token=...` _(AuthorizationLevel.Function)_
Call `GET /api/v2/oauth/tokens/current.json` with `Authorization: Bearer <token>` to verify it. Requires `?code=<FUNCTION_KEY>`.

> Function names are: `StartAuth`, `OAuthCallback`, `ClientCredentialsToken`, `TestToken`.

## Configuration Variables

See **Application Settings** (Azure) or `local.settings.json` (local only):

- `ZENDIESK_BASE_URL` — e.g., `https://support.doorifymls.com`
- `ZENDIESK_CLIENT_ID` — e.g., `voiceflip-doorify`
- `ZENDESK_CLIENT_SECRET` — **client secret** (store in Key Vault)
- `REDIRECT_URI` — `https://<application_function>.azurewebsites.net/api/oauth/callback`
- `SCOPES` — `read and write` (adjust as needed)

> In **Flex Consumption**, `FUNCTIONS_WORKER_RUNTIME` is not defined in Azure. You can use `dotnet-isolated` locally.

## Requirements

- .NET 8 SDK
- Visual Studio 2022 (or VS Code)
- Azurite (for `UseDevelopmentStorage=true`) or a storage account if running locally with real AzureWebJobsStorage.

## Local execution

1. Create `local.settings.json` (not published to Azure):

```json
{
"IsEncrypted": false,
"Values": {
"AzureWebJobsStorage": "UseDevelopmentStorage=true",
"FUNCTIONS_WORKER_RUNTIME": "dotnet-isolated",
"ZENDESK_BASE_URL": "https://support.doorifymls.com",
"ZENDESK_CLIENT_ID": "voiceflip-doorify",
"ZENDESK_CLIENT_SECRET": "REPLACE",
"REDIRECT_URI": "https://voiceflip-auth.azurewebsites.net/api/oauth/callback",
"SCOPES": "read write"
}

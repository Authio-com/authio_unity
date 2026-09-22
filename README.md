# Authio for Unity

Passwordless sign-in for Unity games. Magic link, social OAuth, session refresh, and multi-organization switching.

This is a **player** SDK. It ships inside the game with a publishable key (`pk_live_` / `pk_test_`) and a project id. It is not the server NuGet package `Authio.Sdk`, which targets .NET 8 and must not be referenced from Unity.

Unity **2021.3** or newer. The HTTP and JSON core is .NET Standard 2.1 and is unit-tested without the Unity editor. The Unity assembly uses `UnityWebRequest` so it runs under IL2CPP.

## Install

Unity Package Manager → Add package from git URL:

```
https://github.com/Authio-com/authio_unity.git#v0.1.0
```

The package name is `com.authio.unity`. It depends on `com.unity.nuget.newtonsoft-json`. Unity's editor already ships that package; Package Manager adds it if it is missing.

To follow `main` instead of the tagged release, omit `#v0.1.0`.

## Configure

Create an asset with **Assets → Create → Authio → Config**. Set:

- **publishable key** from the Authio dashboard (`pk_test_…` or `pk_live_…`). Never a secret key. The client refuses `sk_`.
- **project id** (`proj_…`). Every request sends `X-Authio-Project`. Authio rejects calls that do not name a project.
- **api url** defaults to `https://identity.authio.com`, which is the auth-core host. `https://auth-api.authio.com` redirects there. `https://api.authio.com` is the management API and will not accept a publishable key.

Put `AuthioDeepLink` on an object in the first scene and assign the config.

Register the game's redirect URI on the project (for example `mygame://auth`):

- iOS: Player Settings → Other Settings → Supported URL schemes → `mygame`.
- Android: an intent filter on the launcher activity for scheme `mygame` and host `auth`.

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="mygame" android:host="auth" />
</intent-filter>
```

## Sign in

```csharp
// Magic link. Persist happens inside AuthioDeepLink before the message is sent.
await authio.SendMagicLinkAsync("player@example.com", "mygame://auth");

// Social OAuth. Opens the system browser. The pending nonce is saved first,
// because the OS may kill the game while the browser is open.
authio.BeginOAuth(AuthioProviders.Google, "mygame://auth");
```

When the browser returns to `mygame://auth?code=…&client_state_nonce=…`, `AuthioDeepLink` exchanges the one-time code at `POST /v1/auth/session-handoff/exchange` and stores the session. The nonce must match the value minted when the flow started. A mismatched `state` is rejected before any request.

`SignedIn` fires with an `AuthioSession`. `OrgId` is null until the player picks an organization:

```csharp
var orgs = await client.ListOrganizationsAsync(session);
session = await client.SelectOrganizationAsync(session, orgs[0].OrganizationId);
```

On the next launch:

```csharp
var session = authio.LoadSession();
session = await client.EnsureFreshAsync(session); // refreshes only if expires_at has passed
if (!await client.VerifyAsync(session)) { /* sign in again */ }
```

`VerifyAsync` calls `GET /v1/me`. It does not verify the EdDSA signature inside the game. Verify session JWTs on the game server with `Authio.Sdk`.

## What this does not do

- Passkeys. Unity has no Credential Manager / WebAuthn bridge here.
- Secret-key APIs (users, organizations, webhooks, admin portal). Use `Authio.Sdk` on the server.
- A secure enclave. `PlayerPrefs` holds the refresh token in plaintext. Replace `IAuthioSessionStore` if the game needs stronger storage.

## Tests

The editor is not required:

```bash
dotnet test dotnet/Authio.Unity.Tests.csproj
```

# tauri-plugin-auth-session

In-app OAuth authentication for Tauri v2 mobile and desktop apps.

Uses [ASWebAuthenticationSession](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession) on macOS and iOS and [Chrome Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs) on Android to open a secure, native browser session inside your app. The user authenticates with any OAuth/OIDC provider, the provider redirects to your custom URL scheme, and the plugin captures the callback URL and returns it to your app -- no external browser launch, no web-server redirect listener.

## Features

- Single async API: one `start()` call handles the entire browser-based auth flow
- Native browser security: credentials never pass through WebView or app code
- SSO support: shares cookies with Safari (Apple) and Chrome (Android) by default
- Ephemeral sessions: opt out of SSO on Apple platforms with `ephemeral: true`
- PKCE / OAuth 2.0 / OIDC compatible: works with any provider that supports redirect-based authorization (Google, Apple, Auth0, Keycloak, Microsoft, etc.)
- Tauri v2 with full mobile support (iOS + Android)

## Platform Support

| Platform | Auth Method | Min Version | SSO | Status |
|----------|-------------|-------------|-----|--------|
| macOS | ASWebAuthenticationSession | macOS 10.15+ | Safari cookies | Supported |
| iOS | ASWebAuthenticationSession | iOS 13+ | Safari cookies | Supported |
| Android | Chrome Custom Tabs | API 24+ (Android 7) | Chrome cookies | Supported |
| Windows | -- | -- | -- | Stub (returns error) |
| Linux | -- | -- | -- | Stub (returns error) |

On unsupported platforms the plugin registers without error, but calling `start()` returns an error.

## Why This Plugin?

Tauri v2 does not ship a built-in plugin for browser-based OAuth on mobile. On desktop you can spin up a localhost server to receive the OAuth callback, but that approach does not work on iOS or Android.

This plugin solves the problem by using each platform's native in-app browser authentication API. The user stays inside your app, credentials are handled by the system browser (not a WebView), and the redirect is captured automatically via your registered URL scheme. It works the same way on macOS, iOS, and Android, so you can write one auth flow for all three platforms.

## Installation

### Rust

Add the plugin to `src-tauri/Cargo.toml`:

```toml
[dependencies]
tauri-plugin-auth-session = { git = "https://github.com/yanqianglu/tauri-plugin-auth-session" }
```

### JavaScript / TypeScript

```sh
npm install tauri-plugin-auth-session-api
# or
yarn add tauri-plugin-auth-session-api
# or
pnpm add tauri-plugin-auth-session-api
```

Requires `@tauri-apps/api` >= 2.0.0 as a peer dependency.

### Plugin Registration

Register the plugin in `src-tauri/src/lib.rs`:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_auth_session::init())
    // ... other plugins
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
```

### Capabilities

Add the permission to your capability file (e.g. `src-tauri/capabilities/default.json`):

```json
{
  "permissions": ["auth-session:default"]
}
```

## Setup

### Android

The plugin's own `AndroidManifest.xml` declares `AuthSessionActivity`. You need to add an intent filter with your app's callback URL scheme so Android routes the OAuth redirect back to the activity.

In your app's `AndroidManifest.xml` (`src-tauri/gen/android/app/src/main/AndroidManifest.xml`), add:

```xml
<activity
    android:name="app.tauri.auth_session.AuthSessionActivity"
    android:exported="true"
    tools:node="merge">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="myapp" />
    </intent-filter>
</activity>
```

Replace `myapp` with your app's custom URL scheme (the same value you pass as `callbackUrlScheme`).

Make sure the `tools` namespace is declared on the `<manifest>` element:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          xmlns:tools="http://schemas.android.com/tools">
```

### Apple (macOS / iOS)

No additional setup is required. ASWebAuthenticationSession handles callback URL scheme registration automatically.

## Usage

### Basic OAuth Flow

```typescript
import { start } from "tauri-plugin-auth-session-api";

// Build your OAuth authorization URL
const authUrl = new URL("https://your-idp.com/authorize");
authUrl.searchParams.set("client_id", CLIENT_ID);
authUrl.searchParams.set("redirect_uri", "myapp://callback");
authUrl.searchParams.set("response_type", "code");
authUrl.searchParams.set("scope", "openid profile email");
authUrl.searchParams.set("state", state);
authUrl.searchParams.set("code_challenge", codeChallenge);
authUrl.searchParams.set("code_challenge_method", "S256");

try {
  // Opens native browser auth session, returns the full callback URL
  const callbackUrl = await start(authUrl.toString(), "myapp");

  // Extract the authorization code
  const url = new URL(callbackUrl);
  const code = url.searchParams.get("code");

  // Exchange the code for tokens on your backend
  const tokens = await exchangeCodeForTokens(code);
} catch (error) {
  if (error === "user_cancelled") {
    // User dismissed the auth session
  } else {
    console.error("Auth failed:", error);
  }
}
```

### Ephemeral Session (Apple only)

By default, auth sessions share cookies with Safari, enabling SSO. To start a fresh session that does not share cookies or show a "sign in" confirmation prompt:

```typescript
import { start } from "tauri-plugin-auth-session-api";

const callbackUrl = await start(authUrl, "myapp", { ephemeral: true });
```

This sets `prefersEphemeralWebBrowserSession` to `true` on Apple platforms. The option is ignored on Android, where Chrome Custom Tabs always share cookies with Chrome.

### Using invoke Directly

If you prefer not to use the guest-js package, you can call the plugin command directly:

```typescript
import { invoke } from "@tauri-apps/api/core";

const callbackUrl = await invoke<string>("plugin:auth-session|start", {
  authUrl: "https://your-idp.com/authorize?...",
  callbackUrlScheme: "myapp",
  ephemeral: false,
});
```

### Integration with Common Providers

The plugin is provider-agnostic. Any OAuth 2.0 or OIDC provider that supports custom URL scheme redirects will work:

**Keycloak:**
```
https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth
  ?client_id=my-mobile-app
  &redirect_uri=myapp://callback
  &response_type=code
  &scope=openid
  &code_challenge=...
  &code_challenge_method=S256
```

**Auth0:**
```
https://my-tenant.auth0.com/authorize
  ?client_id=...
  &redirect_uri=myapp://callback
  &response_type=code
  &scope=openid profile
  &code_challenge=...
  &code_challenge_method=S256
```

**Google:**
```
https://accounts.google.com/o/oauth2/v2/auth
  ?client_id=...
  &redirect_uri=myapp://callback
  &response_type=code
  &scope=openid email
  &code_challenge=...
  &code_challenge_method=S256
```

## API Reference

### `start(authUrl, callbackUrlScheme, options?)`

Start an in-app authentication session.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `authUrl` | `string` | Full authorization URL including query parameters (client_id, redirect_uri, PKCE challenge, etc.) |
| `callbackUrlScheme` | `string` | The URL scheme portion only (e.g. `"myapp"`), not a full URL. Must match the scheme in your `redirect_uri` and your Android intent filter. |
| `options` | `StartOptions` | Optional. See below. |

**Returns:** `Promise<string>` -- The full callback URL including query parameters (e.g. `myapp://callback?code=abc&state=xyz`).

**Throws:** A string error message. See [Error Handling](#error-handling).

### `StartOptions`

```typescript
interface StartOptions {
  /**
   * If true, the session won't share cookies with Safari (no SSO, no
   * password manager autofill). Apple-only; ignored on Android.
   * Defaults to false.
   */
  ephemeral?: boolean;
}
```

## Error Handling

| Error | Meaning |
|-------|---------|
| `"user_cancelled"` | User dismissed the auth session (pressed back or closed the browser) |
| `"Invalid auth URL: ..."` | The provided URL could not be parsed |
| `"Auth session error: ..."` | Platform-specific error from ASWebAuthenticationSession |
| `"No browser available to handle authentication"` | No Chrome Custom Tabs-capable browser installed (Android) |
| `"In-app auth sessions are only available on Apple and Android platforms"` | Called on Windows or Linux |

## How It Works

1. Your app builds an OAuth authorization URL (typically with PKCE parameters)
2. Your app calls `start(authUrl, callbackUrlScheme)`
3. The plugin opens a native auth browser:
   - **Apple:** ASWebAuthenticationSession presents a system-managed auth sheet anchored to the app's key window
   - **Android:** A transparent bridge activity launches a Chrome Custom Tab
4. The user authenticates with the identity provider in the browser
5. The provider redirects to your custom URL scheme (e.g. `myapp://callback?code=...`)
6. The platform captures the redirect:
   - **Apple:** ASWebAuthenticationSession intercepts the scheme match and fires its completion handler
   - **Android:** The intent filter on `AuthSessionActivity` captures the redirect; the activity returns the URL via `onNewIntent`
7. The plugin resolves the `start()` promise with the full callback URL
8. Your app extracts the authorization code and exchanges it for tokens (typically on your backend)

## Notes

- On **macOS**, ASWebAuthenticationSession opens a floating authentication window managed by the system.
- On **iOS**, it presents a modal sheet anchored to the app's key window with a system-provided "Sign In" confirmation (unless `ephemeral: true`).
- On **Android**, the Chrome Custom Tab runs inside the app's task. If Chrome is not installed, it falls back to the device's default browser. The `ephemeral` option has no effect.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

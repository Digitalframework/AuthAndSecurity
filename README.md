# AuthAndSecurity

Spring Boot + Kotlin app with **Sign in with Google** (OAuth 2.0 / OpenID Connect),
running on `http://localhost:8080`.

## 1. Create Google OAuth credentials

1. Open the [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   and select (or create) a project.
2. Configure the OAuth consent screen — **External** is fine for testing. Add your
   own Google account under **Test users**.
3. **Create credentials → OAuth client ID → Web application**.
4. Under **Authorized redirect URIs**, add exactly:

   ```
   http://localhost:8080/login/oauth2/code/google
   ```

5. Copy the generated **Client ID** and **Client secret**.

## 2. Provide the credentials

The app reads them from the environment and refuses to start without them.

**PowerShell (current session):**

```powershell
$env:GOOGLE_CLIENT_ID = "your-client-id.apps.googleusercontent.com"
$env:GOOGLE_CLIENT_SECRET = "your-client-secret"
```

**Permanently, for your Windows user:**

```powershell
setx GOOGLE_CLIENT_ID "your-client-id.apps.googleusercontent.com"
setx GOOGLE_CLIENT_SECRET "your-client-secret"
```

**Or, without touching environment variables:** copy `.env.example` to `.env` and
fill in the values. That file is git-ignored and imported automatically at startup.

In IntelliJ, the same two variables go in **Run → Edit Configurations →
Environment variables**.

## 3. Run

```powershell
.\mvnw.cmd spring-boot:run
```

Then open <http://localhost:8080> and click **Sign in with Google**.

## How it works

| Path | Purpose |
| --- | --- |
| `/` | Static landing page (`src/main/resources/static/index.html`) |
| `/oauth2/authorization/google` | Starts the login flow (Spring Security built-in) |
| `/login/oauth2/code/google` | Google redirects back here (Spring Security built-in) |
| `/api/me` | Public — the signed-in profile, or `{"authenticated": false}` |
| `/api/csrf` | Public — CSRF token so the page can POST to `/logout` |
| `/logout` | POST, ends the session |

Everything else requires authentication; unauthenticated requests are redirected
straight to Google, since it is the only registered provider.

`SecurityConfig` holds the filter chain, `application.properties` holds the client
registration. Google's authorization/token/user-info URLs come from Spring
Security's built-in `google` provider defaults and do not need to be configured.

## Notes

- Requires **JDK 25** (set in `pom.xml`).
- No database is configured, so Boot starts an in-memory **H2** instance. Login
  state lives in the HTTP session only; nothing is persisted. Set
  `spring.datasource.url` (plus username/password) to switch to the PostgreSQL
  driver that is already on the classpath.
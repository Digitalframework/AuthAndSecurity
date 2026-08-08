# AuthAndSecurity

Spring Boot + Kotlin app with two ways to sign in, running on
`http://localhost:8080`:

- **An emailed sign-in link** — no password at all. You type an address, a link
  arrives, you open it. Built on Spring Security's `oneTimeTokenLogin`.
- **Sign in with Google** (OAuth 2.0 / OpenID Connect).

## Run it

The Google client registration is read from the environment and startup fails
without it, so set those two variables even if you only want to try the email
flow — any placeholder value will do to get the app booted:

```powershell
$env:GOOGLE_CLIENT_ID = "placeholder"
$env:GOOGLE_CLIENT_SECRET = "placeholder"
.\mvnw.cmd spring-boot:run
```

Open <http://localhost:8080>. With no SMTP server configured the app does not
email anything — it writes the link to its own log at WARN level, which is enough
to click the whole flow through locally:

```
No SMTP server configured, so nothing was emailed. Sign-in link for
sam@example.com is http://localhost:8080/login/ott?token=... (valid 10 minutes).
```

For **Sign in with Google** to actually work you need real credentials — see
[Google credentials](#google-credentials) below.

## Signing in with an emailed link

Three pages, all public because they are how an anonymous caller signs in:

| Path | |
| --- | --- |
| `GET /login` | The form. Posts an address to `/ott/generate` |
| `GET /ott/sent` | "Check your inbox" — identical whether or not anything was sent |
| `GET /login/ott?token=…` | Where the emailed link lands: a form holding the token |

and two POSTs, both handled by Spring Security's own filters rather than by any
controller here:

| | |
| --- | --- |
| `POST /ott/generate` | Field `username` — the address. Mints a token and emails it |
| `POST /login/ott` | Field `token` — spends it and establishes the session |

CSRF is on; the Thymeleaf forms carry the hidden field automatically.

The emailed link points at `GET /login/ott`, which only *renders* the token into
a form — spending it needs the POST. That indirection is deliberate: prefetchers
and corporate link scanners follow GETs, and any one of them would otherwise burn
the token before its owner ever saw the page. The same page accepts a pasted
token, which is the fallback when the link itself will not open.

Holding a link proves control of the mailbox it was sent to, and that is the only
claim this flow makes. **There is no user registry behind it, so by default any
address that can receive mail can sign in.** See
[Who can sign in](#who-can-sign-in) to close that.

### Sending real email

Uncommenting `spring.mail.host` is what switches on delivery: Spring Boot only
auto-configures a `JavaMailSender` when that property is set, and `OneTimeTokenConfig`
picks the log-only sender when the bean is absent. Copy `.env.example` to `.env`
(git-ignored, imported at startup) and fill in the SMTP block, or set the same
properties as environment variables.

Gmail needs an **App Password** rather than your account password, and only
offers one once 2-Step Verification is switched on.

Messages go out on an `@Async` thread. The token row is committed before the
send is attempted, so the link works whether or not SMTP has finished — but the
flip side is that a bounced message leaves a usable token nobody receives, and
the user just sees the confirmation page and no email. The resend cooldown is
what lets them recover.

### Tuning

All optional, all overridable in `.env`, `application.properties`, or the
environment. Defaults live in `OneTimeTokenProperties`.

| Property | Default | |
| --- | --- | --- |
| `app.ott.ttl` | `10m` | How long a link stays usable |
| `app.ott.resend-cooldown` | `60s` | Minimum gap between links for one address |
| `app.ott.max-per-window` | `5` | Links one address may request per window |
| `app.ott.window` | `1h` | The span those are counted over |
| `app.ott.retention` | `24h` | How long spent rows are kept before purging |
| `app.ott.from` | `spring.mail.username` | `From` address on the emails |
| `app.ott.base-url` | from the request | Absolute base URL the links are built against |
| `app.ott.allowed-emails` | empty | Addresses allowed to sign in |
| `app.ott.allowed-domains` | empty | Domains allowed to sign in |

`retention` must be at least as long as `window` — the rate limits are counted
from the rows still on disk, so purging earlier would hand out free allowance.
Startup fails if it is shorter.

Set `app.ott.base-url` before putting this behind a proxy that does not send
forwarded headers: without it the link is built from the incoming request and
would name an internal hostname the recipient cannot reach.

### Who can sign in

There is no user registry behind this login: a link proves control of a mailbox
and nothing more. With both allow-lists empty — the default — **any address that
can receive mail can sign in**.

Set either list to close that:

```properties
app.ott.allowed-emails[0]=sam@example.com
app.ott.allowed-domains[0]=example.com
```

An address gets in if it matches either list; everyone else is turned away. The
refusal is deliberately invisible from outside — the same `/ott/sent` page, same
wording, no email — so the endpoint cannot be used to work out who has access.
Refused requests are logged at INFO.

The list is checked twice: once before a link is issued, and again in
`AllowlistUserDetailsService` when one is redeemed. The two run minutes apart, and
an address removed in between must not still be able to spend a link already
sitting in its inbox.

## Google credentials

1. Open the [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   and select (or create) a project.
2. Configure the OAuth consent screen — **External** is fine for testing. Add your
   own Google account under **Test users**.
3. **Create credentials → OAuth client ID → Web application**.
4. Under **Authorized redirect URIs**, add exactly:

   ```
   http://localhost:8080/login/oauth2/code/google
   ```

5. Copy the generated **Client ID** and **Client secret** into `GOOGLE_CLIENT_ID`
   and `GOOGLE_CLIENT_SECRET` — as shell variables, via `setx` for your Windows
   user, in `.env`, or under **Run → Edit Configurations → Environment variables**
   in IntelliJ.

Google's authorization/token/user-info URLs come from Spring Security's built-in
`google` provider defaults and do not need to be configured.

## How it works

| Path | Purpose |
| --- | --- |
| `/` | The page behind the login: who you are, and a sign-out button |
| `/login` | Public — the form, offering both methods |
| `/ott/generate` | Public POST — an address, in exchange for an emailed link |
| `/ott/sent` | Public — confirmation, worded so it gives nothing away |
| `/login/ott` | Public — GET renders the token into a form, POST spends it |
| `/oauth2/authorization/google` | Starts the Google flow (Spring Security built-in) |
| `/login/oauth2/code/google` | Google redirects back here (Spring Security built-in) |
| `/api/user` | The signed-in profile and which method established it |
| `/logout` | POST, ends the session |

Everything else requires authentication. Unauthenticated requests land on
`/login` so the visitor can pick a method, rather than being bounced straight to
Google.

`SecurityConfig` holds the filter chain: `oneTimeTokenLogin` for the emailed
link, `oauth2Login` for Google, form login and HTTP Basic explicitly disabled
because this application has no passwords to check. The email feature lives in
`com.inigo.AuthAndSecurity.onetimetoken`:

| Class | |
| --- | --- |
| `PersistentOneTimeTokenService` | Spring's `OneTimeTokenService`, backed by the database and storing hashes |
| `IssuedToken` / `IssuedTokenRepository` | The `issued_token` table |
| `EmailOneTimeTokenGenerationSuccessHandler` | Builds the link and hands it to the mailer |
| `EmailService` | `SmtpEmailService`, or `LoggingEmailService` with no SMTP host |
| `AllowlistUserDetailsService` | Turns a redeemed token's address into a principal |
| `OneTimeTokenRateLimiter` / `OneTimeTokenRateLimitFilter` | Cooldown and quota, applied before a token is minted |
| `IssuedTokenCleanup` | Scheduled purge of rows past `retention` |

Spring ships `InMemoryOneTimeTokenService` and `JdbcOneTimeTokenService`; neither
is used, because the first drops every outstanding link on restart, both keep
token values in the clear, and the rate limiting needs to count what has been
issued per address out of the same table.

## Security notes

What this does:

- Tokens are **256 bits of `SecureRandom`**, so there is nothing to guess and no
  attempt cap is needed.
- Only a **SHA-256 hash is stored**, so a database dump hands over no working
  logins. A plain digest rather than a password KDF on purpose: redemption
  arrives with nothing but the token, so the row must be found *by* its hash, and
  a KDF's slowness buys nothing against 2^256 candidates.
- **One live link per address.** Requesting another invalidates the previous one,
  so an inbox full of old links is an inbox full of dead ones.
- Links **expire**, are **single use**, and are **bound to one address**.
- **Per-address cooldown and hourly quota**, so an address cannot be mail-bombed.
  This runs *before* the token is minted, so a refusal leaves no row behind and
  no mail in flight — Spring Security's own OTT support has no notion of it.
- The token is **spent by a POST, never by the GET** that renders it, so link
  scanners and prefetchers cannot burn it.
- Signing in **rotates the session id and the CSRF token**, so a session planted
  in someone's browser beforehand cannot be inherited once they log in.
- Refusals are **undifferentiated**: wrong, expired and already-spent tokens all
  fail the same way, and a request for a link always ends on the same page
  whether or not the address is allowed — so neither endpoint can be used to
  probe for accounts. The allowlist is checked *after* the database work rather
  than before, so a refusal is not measurably faster than an acceptance.

What it does **not** do — worth knowing before this faces the internet:

- **No per-IP or global send limit.** The quota is per address, so a caller
  working through many addresses can still burn your SMTP reputation. Add a
  per-IP limiter, or a global cap, before exposing this publicly.
- **Any mailbox can sign in** unless an allowlist is set, as described above.
- **Links go to the log when no SMTP host is set.** That is a local-development
  convenience and nothing else; the WARN on every send is deliberate.
- **A failed send is logged and dropped.** The user sees the confirmation page
  either way and has to wait out the cooldown to retry.
- **Rate-limit state lives in the `issued_token` table**, so on the default
  in-memory H2 it resets whenever the app restarts.
- Sessions are in-memory, single-instance. Nothing here survives a restart.

## Notes

- Requires **JDK 25** (set in `pom.xml`).
- No database is configured, so Boot starts an in-memory **H2** instance and
  creates `issued_token` in it automatically. Set `spring.datasource.url` (plus
  username/password) to switch to the PostgreSQL driver already on the classpath —
  but note that Boot only defaults `ddl-auto` to `create-drop` for embedded
  databases, so against PostgreSQL you must create the table yourself or set
  `spring.jpa.hibernate.ddl-auto=update` for a throwaway setup.
- `.\mvnw.cmd test` covers the flow end to end: token issue and redemption in
  `PersistentOneTimeTokenServiceTest`, the limits in `OneTimeTokenRateLimiterTest`,
  and the HTTP/session behaviour in `OneTimeTokenLoginFlowTest`.

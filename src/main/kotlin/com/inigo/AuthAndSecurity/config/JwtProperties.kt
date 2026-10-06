package com.inigo.AuthAndSecurity.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.Resource
import java.time.Duration

/**
 * How the access tokens handed to other services are signed and stamped, all under
 * the `app.jwt.` prefix.
 *
 * These tokens exist so a second application — generation-backend — can be told who
 * the caller is and what they may do without sharing this one's session store or
 * its user table. Everything it needs is inside the token, and the signature is what
 * makes that safe to believe.
 */
@ConfigurationProperties(prefix = "app.jwt")
data class JwtProperties(

    /**
     * The `iss` claim, and what the recipient checks the token came from. Must match
     * `spring.security.oauth2.resourceserver.jwt.issuer-uri` over there, character
     * for character, or every token is rejected.
     */
    val issuer: String = "http://localhost:8080",

    /**
     * The `aud` claim: who the token is *for*. A recipient that checks it cannot be
     * handed a token minted for somewhere else — which matters the moment there is
     * a third service, because otherwise any of them can replay a token at any other.
     */
    val audience: String = "generation-backend",

    /**
     * How long an issued token stays valid. Short on purpose: nothing can revoke one
     * before it expires, so a permission taken away in the user table stays spendable
     * until then. Fifteen minutes is the window in which that is true.
     */
    val ttl: Duration = Duration.ofMinutes(15),

    /**
     * PKCS#8 PEM holding the RSA private key that signs tokens, e.g.
     * `file:./jwt-signing-key.pem`. Left unset — together with [publicKey] — a key
     * pair is generated at startup instead, which is fine locally and wrong anywhere
     * with more than one instance or more than one restart: see [JwtConfig].
     */
    val privateKey: Resource? = null,

    /** X.509 PEM holding the matching public key, published at the JWKS endpoint. */
    val publicKey: Resource? = null,
) {
    /** Whether a key pair was supplied rather than left to be generated. */
    val hasConfiguredKeys: Boolean get() = privateKey != null && publicKey != null

    init {
        require(issuer.startsWith("http://") || issuer.startsWith("https://")) {
            "app.jwt.issuer must be an absolute URL, was '$issuer'"
        }
        require(audience.isNotBlank()) { "app.jwt.audience must not be blank" }
        require(!ttl.isNegative && !ttl.isZero) { "app.jwt.ttl must be positive, was $ttl" }
        // Half a pair is the one case that must not start: it would silently fall
        // back to a generated key while looking configured.
        require((privateKey == null) == (publicKey == null)) {
            "app.jwt.private-key and app.jwt.public-key must be set together, or neither"
        }
    }
}

package com.inigo.AuthAndSecurity.controller

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Publishes the public half of the signing key, so anything verifying a token this
 * application issued can fetch what it needs instead of being configured with a copy.
 *
 * Open to everyone, and that is not a lapse: a public key verifies signatures and
 * cannot produce them. Keeping it secret would buy nothing and would mean shipping
 * it by hand to every service that needs it, then again on every rotation.
 */
@RestController
class JwkSetController(
    private val jwtSigningKey: RSAKey,
) {

    /**
     * `toPublicJWK()` is what keeps the private exponent out of the response. The
     * bean holds both halves — the encoder needs them — so this is the one line
     * standing between the signing key and the open internet, and it is why the key
     * is not simply serialized as-is.
     */
    @GetMapping(JWK_SET_PATH, produces = ["application/json"])
    fun jwks(): Map<String, Any> = JWKSet(jwtSigningKey.toPublicJWK()).toJSONObject()

    companion object {
        /**
         * The conventional location, which is what a verifier configured with only an
         * `issuer-uri` will go looking for.
         */
        const val JWK_SET_PATH: String = "/.well-known/jwks.json"
    }
}

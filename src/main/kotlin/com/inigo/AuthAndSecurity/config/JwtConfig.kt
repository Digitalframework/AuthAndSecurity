package com.inigo.AuthAndSecurity.config

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.Resource
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * The signing key behind the access tokens other services are given, and the encoder
 * that uses it.
 *
 * Signing is asymmetric on purpose. A shared secret would have to be copied into
 * every service that verifies a token, and each copy is somewhere it can leak from —
 * and anywhere it leaks to can then *mint* tokens, not merely read them. With RSA
 * the private half never leaves this application; the public half is published at
 * `/.well-known/jwks.json` for anyone to fetch, because that is all a verifier needs.
 *
 * The library is already on the classpath — `spring-boot-starter-security-oauth2-\
 * resource-server` brings Nimbus with it — so none of this adds a dependency.
 */
@Configuration
class JwtConfig {

    /**
     * The key pair, as a JWK so both the encoder and the JWKS endpoint can be built
     * from one object rather than agreeing separately on a key id.
     *
     * The id is the key's own thumbprint rather than a random value, which means a
     * configured key keeps the same `kid` across restarts and across instances. A
     * verifier that has already cached the key set therefore still recognises it.
     */
    @Bean
    fun jwtSigningKey(properties: JwtProperties): RSAKey {
        val (publicKey, privateKey) = if (properties.hasConfiguredKeys) {
            readConfiguredPair(properties.publicKey!!, properties.privateKey!!)
        } else {
            generateEphemeralPair()
        }

        return RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .keyIDFromThumbprint()
            .build()
    }

    @Bean
    fun jwkSource(jwtSigningKey: RSAKey): JWKSource<SecurityContext> =
        ImmutableJWKSet(JWKSet(jwtSigningKey))

    @Bean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext>): JwtEncoder = NimbusJwtEncoder(jwkSource)

    /** The algorithm the encoder signs with, named once so the header cannot drift. */
    @Bean
    fun jwtSignatureAlgorithm(): SignatureAlgorithm = SignatureAlgorithm.RS256

    private fun readConfiguredPair(publicPem: Resource, privatePem: Resource): Pair<RSAPublicKey, RSAPrivateKey> {
        val factory = KeyFactory.getInstance("RSA")
        val public = factory.generatePublic(X509EncodedKeySpec(decodePem(publicPem))) as RSAPublicKey
        val private = factory.generatePrivate(PKCS8EncodedKeySpec(decodePem(privatePem))) as RSAPrivateKey
        log.info("Signing access tokens with the configured RSA key from {}", privatePem.description)
        return public to private
    }

    /**
     * What happens with nothing configured. Usable for a local run and nothing else:
     * the key dies with the process, so every restart invalidates every token already
     * handed out, and two instances behind a load balancer sign with different keys —
     * a token minted by one is rejected by the other, intermittently, which is a
     * miserable thing to debug. Hence the warning rather than silence.
     */
    private fun generateEphemeralPair(): Pair<RSAPublicKey, RSAPrivateKey> {
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(KEY_SIZE) }.generateKeyPair()
        log.warn(
            "No app.jwt.private-key configured — generating a throwaway RSA key. Tokens issued now " +
                "stop verifying at the next restart. Set app.jwt.private-key and app.jwt.public-key " +
                "for anything but a local run.",
        )
        return pair.public as RSAPublicKey to pair.private as RSAPrivateKey
    }

    /**
     * Strips the `-----BEGIN ...-----` armour and decodes what is left. Deliberately
     * indifferent to the label on those lines: the caller already knows which of the
     * two keys it asked for, and the [KeyFactory] rejects a mismatch anyway.
     */
    private fun decodePem(resource: Resource): ByteArray {
        val body = resource.inputStream.use { it.readBytes() }
            .decodeToString()
            .lineSequence()
            .filterNot { it.startsWith("-----") }
            .joinToString(separator = "")
            .filterNot { it.isWhitespace() }

        require(body.isNotEmpty()) { "${resource.description} contains no key material" }
        return Base64.getDecoder().decode(body)
    }

    private companion object {
        val log = LoggerFactory.getLogger(JwtConfig::class.java)

        /** 2048 is the floor RS256 verifiers accept; larger only slows signing down. */
        const val KEY_SIZE: Int = 2048
    }
}

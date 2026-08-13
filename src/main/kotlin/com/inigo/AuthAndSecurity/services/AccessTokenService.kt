package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.config.JwtProperties
import com.inigo.AuthAndSecurity.dto.AccessTokenResponse
import com.inigo.AuthAndSecurity.entity.AppUser
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.stereotype.Service
import java.time.Clock
import java.time.temporal.ChronoUnit

/**
 * Turns a signed-in session into a token another service can act on.
 *
 * The claims are read from the user table at the moment of issue rather than from
 * the session, for the same reason [CurrentUserService] does it: the session carries
 * only an email address, and permissions live in the table where they can change.
 * A token is a snapshot of that table taken now — which is exactly why the lifetime
 * in [JwtProperties.ttl] is short.
 */
@Service
class AccessTokenService(
    private val encoder: JwtEncoder,
    private val properties: JwtProperties,
    private val algorithm: SignatureAlgorithm,
    private val clock: Clock,
) {

    fun issueFor(user: AppUser): AccessTokenResponse {
        // JWT times are whole seconds; truncating here means the expiry reported to
        // the caller is the one actually encoded rather than a rounded-off cousin.
        val issuedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS)
        val expiresAt = issuedAt.plus(properties.ttl)
        val roles = user.permissions.map { it.name }.sorted()

        val claims = JwtClaimsSet.builder()
            .issuer(properties.issuer)
            .audience(listOf(properties.audience))
            // The row's id, not the address: an email can be corrected, and anything
            // the other service stores against a subject would then be orphaned.
            .subject(user.userId.toString())
            .issuedAt(issuedAt)
            .expiresAt(expiresAt)
            .claim(EMAIL_CLAIM, user.email)
            // Bare names — "USER", "ADMIN" — because the ROLE_ prefix is Spring
            // Security's own convention and the recipient re-applies it. Baking it
            // in would leak this framework into the token format.
            .claim(ROLES_CLAIM, roles)
            .build()

        val header = JwsHeader.with(algorithm).build()
        val token = encoder.encode(JwtEncoderParameters.from(header, claims))

        return AccessTokenResponse(
            accessToken = token.tokenValue,
            expiresIn = properties.ttl.toSeconds(),
            roles = roles,
        )
    }

    companion object {
        /** Claim the recipient maps onto authorities. */
        const val ROLES_CLAIM: String = "roles"

        /** Who the subject is, for logs and display over there. Never for authorization. */
        const val EMAIL_CLAIM: String = "email"
    }
}

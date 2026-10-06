package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.entity.IssuedToken
import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenProperties
import com.inigo.AuthAndSecurity.repositories.IssuedTokenRepository
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.ott.DefaultOneTimeToken
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest
import org.springframework.security.authentication.ott.OneTimeToken
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken
import org.springframework.security.authentication.ott.OneTimeTokenService
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.util.Base64
import java.util.HexFormat
import java.util.Locale

/**
 * Stores one-time sign-in tokens in the database, hashed.
 *
 * Spring Security ships [org.springframework.security.authentication.ott.InMemoryOneTimeTokenService]
 * and [org.springframework.security.authentication.ott.JdbcOneTimeTokenService]. Neither
 * is used here: the in-memory one drops every outstanding link on restart, and both
 * keep token values in the clear. This one also has to share storage with the rate
 * limiting in [OneTimeTokenRateLimiterService], which counts what has been issued per
 * address.
 */
@Service
class PersistentOneTimeTokenService(
    private val tokens: IssuedTokenRepository,
    private val properties: OneTimeTokenProperties,
    private val clock: Clock,
) : OneTimeTokenService {

    private val log = LoggerFactory.getLogger(javaClass)
    private val random = SecureRandom()

    @Transactional
    override fun generate(request: GenerateOneTimeTokenRequest): OneTimeToken {
        val email = normalizeEmail(request.username)
        val now = clock.instant()
        // Always populated — Spring's resolver defaults it to five minutes when
        // nothing is configured, which is why SecurityConfig pushes `app.ott.ttl`
        // onto the resolver rather than applying it here. A caller that builds the
        // request itself is taken at its word.
        val expiresAt = now.plus(request.expiresIn)

        // At most one link per address is ever live, so a mailbox that receives
        // several only ever has the newest one work. Without this, every link in
        // the inbox would stay usable until it expired on its own.
        tokens.invalidateLiveTokensFor(email, now)

        val tokenValue = generateTokenValue()
        tokens.save(
            IssuedToken(
                email = email,
                tokenHash = hash(tokenValue),
                createdAt = now,
                expiresAt = expiresAt,
            )
        )

        log.info("Issued a sign-in link for {}", email)
        return DefaultOneTimeToken(tokenValue, email, expiresAt)
    }

    /**
     * Redeems a token, or returns `null` if it was wrong, expired, or already
     * spent. The caller gets one undifferentiated failure on purpose — which of
     * those it was is not the submitter's business.
     */
    @Transactional
    override fun consume(authenticationToken: OneTimeTokenAuthenticationToken): OneTimeToken? {
        val submitted = authenticationToken.tokenValue ?: return null
        val now = clock.instant()

        val candidate = tokens.findByTokenHash(hash(submitted)) ?: return null
        if (candidate.invalidatedAt != null || now.isAfter(candidate.expiresAt)) {
            return null
        }

        candidate.invalidatedAt = now
        tokens.save(candidate)

        log.info("Redeemed a sign-in link for {}", candidate.email)
        return DefaultOneTimeToken(submitted, candidate.email, candidate.expiresAt)
    }

    /** 256 bits, URL-safe and unpadded so it survives being pasted out of an email. */
    private fun generateTokenValue(): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun hash(tokenValue: String): String =
        HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(tokenValue.toByteArray(Charsets.UTF_8))
        )

    private fun normalizeEmail(rawEmail: String): String = rawEmail.trim().lowercase(Locale.ROOT)
}
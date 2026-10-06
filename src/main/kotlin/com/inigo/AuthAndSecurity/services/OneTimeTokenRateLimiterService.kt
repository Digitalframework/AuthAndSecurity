package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenProperties
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import com.inigo.AuthAndSecurity.repositories.IssuedTokenRepository
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Duration
import java.util.Locale

/** What came of asking for a sign-in link. */
sealed interface LinkRequestDecision {

    /** Go ahead and issue one. */
    data object Allowed : LinkRequestDecision

    /**
     * Refused, but the caller must not be told why: the address is not on the
     * allowlist, or has no confirmed account behind it. Saying so would turn this
     * endpoint into a way of asking who has access, and into a way of listing which
     * addresses are registered. Handled by doing nothing and reporting success.
     */
    data object SilentlyRefused : LinkRequestDecision

    /** A link went out moments ago; [retryAfter] is the wait before another. */
    data class TooSoon(val retryAfter: Duration) : LinkRequestDecision

    /** The address has used up its allowance for the current window. */
    data object QuotaExceeded : LinkRequestDecision
}

/** Which of the two pages is asking, since they do not accept the same addresses. */
enum class LinkPurpose {

    /** Only a confirmed account may be sent one. */
    SIGN_IN,

    /** An address with no account is exactly who this is for. */
    REGISTRATION,
}

/**
 * Decides whether an address may be sent another sign-in link.
 *
 * Spring Security's one-time token support has no notion of rate limiting — it
 * will mint a token for every request that reaches it. That is fine for the token
 * itself, which is unguessable, but it leaves the mail path open: without a bound,
 * anyone can point the generate endpoint at someone else's address and keep it
 * ringing. This is what supplies that bound, and it runs *before* a token is
 * generated rather than inside the token service, so a refusal never leaves a row
 * behind or an email in flight.
 */
@Service
class OneTimeTokenRateLimiterService(
    private val tokens: IssuedTokenRepository,
    private val users: AppUserRepository,
    private val properties: OneTimeTokenProperties,
    private val clock: Clock,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional(readOnly = true)
    fun decide(rawEmail: String, purpose: LinkPurpose): LinkRequestDecision {
        val email = normalizeEmail(rawEmail)
        val now = clock.instant()

        // The allowlist and the account lookup are checked last, even though they
        // are the cheapest tests and the ones most likely to refuse. Checking them
        // first would return before either query below had run, making a refusal
        // measurably faster than an acceptance and handing back exactly the answer
        // the silent refusal is there to withhold. An address that is refused has
        // no rows, so neither limit below can fire for it — running the queries
        // anyway costs nothing but keeps the two paths the same shape, and for the
        // same reason the account lookup runs whether or not it will be consulted.
        val previous = tokens.findFirstByEmailOrderByCreatedAtDesc(email)
        val recentlyIssued = tokens.countByEmailAndCreatedAtAfter(email, now.minus(properties.window))
        val registered = users.existsByEmailAndVerifiedAtIsNotNull(email)

        if (previous != null) {
            val nextAllowedAt = previous.createdAt.plus(properties.resendCooldown)
            if (now.isBefore(nextAllowedAt)) {
                return LinkRequestDecision.TooSoon(Duration.between(now, nextAllowedAt))
            }
        }

        if (recentlyIssued >= properties.maxPerWindow) {
            log.info("Refusing another sign-in link for {}: {} already issued this window", email, recentlyIssued)
            return LinkRequestDecision.QuotaExceeded
        }

        if (!properties.allows(email)) {
            log.info("Refusing a link for {}: not on the allowlist", email)
            return LinkRequestDecision.SilentlyRefused
        }

        // Nobody may be sent a sign-in link to an account that does not exist yet.
        // Registration is the door for those, and it is the only one that writes a
        // row — otherwise anyone could sign in as any address they could receive
        // mail at, which is what this application used to do.
        if (purpose == LinkPurpose.SIGN_IN && !registered) {
            log.info("Refusing a sign-in link for {}: no confirmed account", email)
            return LinkRequestDecision.SilentlyRefused
        }

        return LinkRequestDecision.Allowed
    }

    private fun normalizeEmail(rawEmail: String): String = rawEmail.trim().lowercase(Locale.ROOT)
}
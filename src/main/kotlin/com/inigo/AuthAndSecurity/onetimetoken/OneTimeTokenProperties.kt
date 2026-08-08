package com.inigo.AuthAndSecurity.onetimetoken

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration
import java.util.Locale

/**
 * Tuning knobs for the emailed sign-in link, all under the `app.ott.` prefix.
 * The defaults are the ones the app ships with; see README.md.
 *
 * There is no attempt cap and no code length here, unlike the six-digit code this
 * replaced. The token is 256 bits of randomness, so there is nothing to guess and
 * nothing for a cap to protect. What still matters is how many messages one
 * address can provoke, which is what the cooldown and window below bound.
 */
@ConfigurationProperties(prefix = "app.ott")
data class OneTimeTokenProperties(

    /** How long a freshly issued link stays usable. */
    val ttl: Duration = Duration.ofMinutes(10),

    /** Minimum gap between two links for the same address. */
    val resendCooldown: Duration = Duration.ofSeconds(60),

    /** Links one address may request per [window], to limit mail-bombing. */
    val maxPerWindow: Int = 5,

    /** The span [maxPerWindow] is counted over. */
    val window: Duration = Duration.ofHours(1),

    /**
     * How long spent tokens are kept before being purged. Must outlast [window],
     * because the rate limits are counted from the rows still on disk.
     */
    val retention: Duration = Duration.ofHours(24),

    /**
     * `From` address on the emails. Falls back to `spring.mail.username` when
     * unset, which is what most SMTP providers expect anyway.
     */
    val from: String? = null,

    /**
     * Absolute base URL to build sign-in links against, e.g.
     * `https://app.example.com`. Left unset, the link is built from the incoming
     * request, which is right for local runs but wrong behind a proxy that does
     * not send forwarded headers — the link would point at an internal hostname
     * the recipient cannot reach.
     */
    val baseUrl: String? = null,

    /**
     * Individual addresses allowed to sign in. Combined with [allowedDomains]:
     * an address gets in if it matches either list.
     */
    val allowedEmails: List<String> = emptyList(),

    /**
     * Domains whose addresses may sign in, written bare (`example.com`) or with
     * a leading `@`.
     */
    val allowedDomains: List<String> = emptyList(),
) {
    /** Folded to the same shape [allows] receives, so matching is a plain lookup. */
    private val allowedEmailSet: Set<String> =
        allowedEmails.map { it.trim().lowercase(Locale.ROOT) }.filter { it.isNotEmpty() }.toSet()

    private val allowedDomainSet: Set<String> =
        allowedDomains.map { it.trim().lowercase(Locale.ROOT).removePrefix("@") }.filter { it.isNotEmpty() }.toSet()

    /**
     * Whether [email] — already normalized — may be sent a link at all.
     *
     * With both lists empty the login is open to any mailbox, which is the
     * default: holding a link proves control of an address and nothing more, and
     * there is no user registry behind it. Setting either list turns that into a
     * closed door.
     */
    fun allows(email: String): Boolean {
        if (allowedEmailSet.isEmpty() && allowedDomainSet.isEmpty()) return true
        if (email in allowedEmailSet) return true
        val domain = email.substringAfterLast('@', missingDelimiterValue = "")
        return domain.isNotEmpty() && domain in allowedDomainSet
    }

    init {
        require(maxPerWindow >= 1) { "app.ott.max-per-window must be at least 1, was $maxPerWindow" }
        require(!ttl.isNegative && !ttl.isZero) { "app.ott.ttl must be positive, was $ttl" }
        // A typo here fails open in the worst way — an unusable entry would just
        // silently never match — so bad input stops startup instead.
        allowedEmailSet.forEach {
            require('@' in it) { "app.ott.allowed-emails must contain addresses, was '$it'" }
        }
        allowedDomainSet.forEach {
            require('@' !in it && '.' in it) {
                "app.ott.allowed-domains must contain bare domains like 'example.com', was '$it'"
            }
        }
        require(retention >= window) {
            "app.ott.retention ($retention) must be at least as long as the rate-limit window ($window), " +
                "otherwise the rows the limits are counted from get purged too early"
        }
        baseUrl?.let {
            require(it.startsWith("http://") || it.startsWith("https://")) {
                "app.ott.base-url must be an absolute URL, was '$it'"
            }
        }
    }
}
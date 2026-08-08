package com.inigo.AuthAndSecurity.onetimetoken

import com.inigo.AuthAndSecurity.repositories.IssuedTokenRepository
import com.inigo.AuthAndSecurity.services.LinkRequestDecision
import com.inigo.AuthAndSecurity.services.OneTimeTokenRateLimiterService
import com.inigo.AuthAndSecurity.services.PersistentOneTimeTokenService
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

@DataJpaTest
class OneTimeTokenRateLimiterTest {

    @Autowired
    private lateinit var tokens: IssuedTokenRepository

    private val clock = MutableClock()

    @BeforeEach
    fun setUp() {
        clock.reset()
    }

    private fun limiter(properties: OneTimeTokenProperties) =
        OneTimeTokenRateLimiterService(tokens, properties, clock)

    /** Issues a token the way the generate filter would, so rows exist to count. */
    private fun issue(properties: OneTimeTokenProperties, email: String) {
        PersistentOneTimeTokenService(tokens, properties, clock)
            .generate(GenerateOneTimeTokenRequest(email, properties.ttl))
    }

    @Test
    fun `allows a first request`() {
        val properties = OneTimeTokenProperties()

        assertEquals(LinkRequestDecision.Allowed, limiter(properties).decide("sam@example.com"))
    }

    @Test
    fun `holds off a resend inside the cooldown`() {
        val properties = OneTimeTokenProperties(resendCooldown = Duration.ofSeconds(60))
        issue(properties, "sam@example.com")

        clock.advance(Duration.ofSeconds(15))
        val decision = limiter(properties).decide("sam@example.com")

        val tooSoon = assertIs<LinkRequestDecision.TooSoon>(decision)
        assertEquals(45, tooSoon.retryAfter.seconds)
    }

    @Test
    fun `allows a resend once the cooldown has passed`() {
        val properties = OneTimeTokenProperties(resendCooldown = Duration.ofSeconds(60))
        issue(properties, "sam@example.com")

        clock.advance(Duration.ofSeconds(61))

        assertEquals(LinkRequestDecision.Allowed, limiter(properties).decide("sam@example.com"))
    }

    @Test
    fun `refuses once the window quota is used up`() {
        val properties = OneTimeTokenProperties(
            resendCooldown = Duration.ZERO,
            maxPerWindow = 3,
            window = Duration.ofHours(1),
        )
        repeat(3) {
            issue(properties, "sam@example.com")
            clock.advance(Duration.ofSeconds(1))
        }

        assertEquals(LinkRequestDecision.QuotaExceeded, limiter(properties).decide("sam@example.com"))
    }

    @Test
    fun `the quota is per address`() {
        val properties = OneTimeTokenProperties(resendCooldown = Duration.ZERO, maxPerWindow = 1)
        issue(properties, "sam@example.com")
        clock.advance(Duration.ofSeconds(1))

        assertEquals(LinkRequestDecision.QuotaExceeded, limiter(properties).decide("sam@example.com"))
        assertEquals(LinkRequestDecision.Allowed, limiter(properties).decide("alex@example.com"))
    }

    @Test
    fun `the quota lapses once the window rolls past`() {
        val properties = OneTimeTokenProperties(
            resendCooldown = Duration.ZERO,
            maxPerWindow = 1,
            window = Duration.ofHours(1),
        )
        issue(properties, "sam@example.com")

        clock.advance(Duration.ofHours(1).plusSeconds(1))

        assertEquals(LinkRequestDecision.Allowed, limiter(properties).decide("sam@example.com"))
    }

    @Test
    fun `an address off the allowlist is refused without being told`() {
        val properties = OneTimeTokenProperties(allowedDomains = listOf("example.com"))

        assertEquals(
            LinkRequestDecision.SilentlyRefused,
            limiter(properties).decide("intruder@elsewhere.test"),
        )
    }

    @Test
    fun `an allowlist admits by exact address or by domain`() {
        val properties = OneTimeTokenProperties(
            allowedEmails = listOf("Named@Elsewhere.test"),
            allowedDomains = listOf("@example.com"),
        )
        val limiter = limiter(properties)

        assertEquals(LinkRequestDecision.Allowed, limiter.decide("anyone@example.com"))
        assertEquals(LinkRequestDecision.Allowed, limiter.decide("NAMED@elsewhere.test"))
        assertEquals(LinkRequestDecision.SilentlyRefused, limiter.decide("other@elsewhere.test"))
    }

    @Test
    fun `no allowlist means any mailbox may sign in`() {
        val properties = OneTimeTokenProperties()

        assertEquals(LinkRequestDecision.Allowed, limiter(properties).decide("anyone@anywhere.test"))
    }

    @Test
    fun `a silent refusal still runs the same queries as an acceptance`() {
        // Guards the ordering in decide(): the allowlist is checked last precisely
        // so a refusal is not the conspicuously fast answer. If someone reorders it
        // for tidiness, a refused address would stop consuming quota — which is what
        // this asserts against.
        val properties = OneTimeTokenProperties(
            resendCooldown = Duration.ZERO,
            maxPerWindow = 1,
            allowedDomains = listOf("example.com"),
        )
        issue(properties, "intruder@elsewhere.test")
        clock.advance(Duration.ofSeconds(1))

        assertTrue(
            limiter(properties).decide("intruder@elsewhere.test") is LinkRequestDecision.QuotaExceeded,
            "the rate-limit queries must run before the allowlist check",
        )
    }
}
package com.inigo.AuthAndSecurity.onetimetoken

import com.inigo.AuthAndSecurity.repositories.IssuedTokenRepository
import com.inigo.AuthAndSecurity.services.PersistentOneTimeTokenService
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@DataJpaTest
class PersistentOneTimeTokenServiceTest {

    @Autowired
    private lateinit var tokens: IssuedTokenRepository

    private val properties = OneTimeTokenProperties()
    private val clock = MutableClock()
    private lateinit var service: PersistentOneTimeTokenService

    @BeforeEach
    fun setUp() {
        clock.reset()
        service = PersistentOneTimeTokenService(tokens, properties, clock)
    }

    private fun generate(email: String) =
        service.generate(GenerateOneTimeTokenRequest(email, properties.ttl))

    @Test
    fun `issues a token for the address, normalized`() {
        val issued = generate("  Sam@Example.COM ")

        assertEquals("sam@example.com", issued.username)
        assertEquals(clock.instant().plus(properties.ttl), issued.expiresAt)
        assertTrue(issued.tokenValue.length >= 40, "expected a high-entropy token, got '${issued.tokenValue}'")
    }

    @Test
    fun `stores only a hash of the token`() {
        val issued = generate("sam@example.com")

        val row = tokens.findAll().single()
        assertNotEquals(issued.tokenValue, row.tokenHash)
        // Hex-encoded SHA-256.
        assertEquals(64, row.tokenHash.length)
        assertTrue(row.tokenHash.all { it.isDigit() || it in 'a'..'f' })
    }

    @Test
    fun `redeems a token once and only once`() {
        val issued = generate("sam@example.com")

        val consumed = service.consume(OneTimeTokenAuthenticationToken.unauthenticated(issued.tokenValue))
        assertNotNull(consumed)
        assertEquals("sam@example.com", consumed.username)

        assertNull(
            service.consume(OneTimeTokenAuthenticationToken.unauthenticated(issued.tokenValue)),
            "a spent token must not be redeemable again",
        )
    }

    @Test
    fun `refuses a token past its expiry`() {
        val issued = generate("sam@example.com")

        clock.advance(properties.ttl.plusSeconds(1))

        assertNull(service.consume(OneTimeTokenAuthenticationToken.unauthenticated(issued.tokenValue)))
    }

    @Test
    fun `refuses a token that was never issued`() {
        generate("sam@example.com")

        assertNull(service.consume(OneTimeTokenAuthenticationToken.unauthenticated("not-a-real-token")))
    }

    @Test
    fun `issuing a new token retires the previous one`() {
        val first = generate("sam@example.com")
        clock.advance(Duration.ofSeconds(1))
        val second = generate("sam@example.com")

        assertNull(
            service.consume(OneTimeTokenAuthenticationToken.unauthenticated(first.tokenValue)),
            "only the newest link for an address should work",
        )
        assertNotNull(service.consume(OneTimeTokenAuthenticationToken.unauthenticated(second.tokenValue)))
    }

    @Test
    fun `a token is redeemed by whoever holds it, whatever address they claim`() {
        // The submit form sends only the token; there is no address to disagree
        // with. This pins that the address comes off the stored row.
        val issued = generate("sam@example.com")

        val consumed = service.consume(OneTimeTokenAuthenticationToken.unauthenticated(issued.tokenValue))

        assertEquals("sam@example.com", consumed?.username)
    }
}
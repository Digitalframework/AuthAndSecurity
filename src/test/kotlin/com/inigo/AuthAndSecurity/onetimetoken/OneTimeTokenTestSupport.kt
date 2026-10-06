package com.inigo.AuthAndSecurity.onetimetoken

import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import com.inigo.AuthAndSecurity.services.EmailService
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset

/**
 * Lets a test say what "now" is, so expiry and cooldowns can be exercised without
 * anything sleeping.
 */
class MutableClock(var now: Instant = START) : Clock() {

    override fun instant(): Instant = now

    override fun getZone(): ZoneId = ZoneOffset.UTC

    override fun withZone(zone: ZoneId): Clock = this

    fun advance(amount: Duration) {
        now = now.plus(amount)
    }

    fun reset() {
        now = START
    }

    companion object {
        val START: Instant = Instant.parse("2026-01-01T12:00:00Z")
    }
}

/** Captures what would have gone out by email, tokens included. */
class RecordingEmailService : EmailService {

    data class Sent(
        val email: String,
        val link: String,
        val token: String,
        val validFor: Duration,
        /** Which of the two messages this was — the wording is the only difference. */
        val verification: Boolean = false,
    )

    private val sent = mutableListOf<Sent>()

    override fun sendSignInLink(email: String, link: String, token: String, validFor: Duration) {
        sent += Sent(email, link, token, validFor)
    }

    override fun sendVerificationLink(
        email: String,
        firstname: String,
        link: String,
        token: String,
        validFor: Duration,
    ) {
        sent += Sent(email, link, token, validFor, verification = true)
    }

    val count: Int get() = sent.size

    val all: List<Sent> get() = sent.toList()

    fun lastFor(email: String): Sent = sent.last { it.email == email }

    fun clear() = sent.clear()
}

/**
 * Swaps in the two seams the production beans were written around. Both are
 * `@Primary` so they win the injection points without needing bean overriding.
 */
@TestConfiguration
class OneTimeTokenTestConfig {

    @Bean
    @Primary
    fun testClock(): MutableClock = MutableClock()

    @Bean
    @Primary
    fun testEmailService(): RecordingEmailService = RecordingEmailService()
}
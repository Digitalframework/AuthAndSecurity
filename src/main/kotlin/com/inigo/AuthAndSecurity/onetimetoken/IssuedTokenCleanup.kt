package com.inigo.AuthAndSecurity.onetimetoken

import com.inigo.AuthAndSecurity.repositories.IssuedTokenRepository
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import java.time.Clock

/**
 * Spent and expired tokens are kept for a while because the rate limits are
 * counted from them, but not forever — otherwise the table only ever grows.
 */
@Component
class IssuedTokenCleanup(
    private val tokens: IssuedTokenRepository,
    private val properties: OneTimeTokenProperties,
    private val clock: Clock,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Scheduled(initialDelayString = "PT1M", fixedDelayString = "PT15M")
    @Transactional
    fun purgeOldTokens() {
        val removed = tokens.deleteCreatedBefore(clock.instant().minus(properties.retention))
        if (removed > 0) {
            log.debug("Purged {} sign-in tokens older than {}", removed, properties.retention)
        }
    }
}
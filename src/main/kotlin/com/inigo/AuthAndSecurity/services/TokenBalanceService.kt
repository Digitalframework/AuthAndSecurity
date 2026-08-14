package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.dto.TokenBalanceResponse
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.server.ResponseStatusException
import java.util.UUID

/**
 * Reading and spending a balance on behalf of a token holder rather than a session.
 *
 * Every other route to the balance in this application starts from a signed-in
 * browser — [CurrentUserService] and [PaypalService] both resolve a session to a row.
 * These two start from a verified JWT instead, so the owner is the token's subject
 * and is never taken from the request: see [SpendTokensRequest], which deliberately
 * has no user field.
 */
@Service
class TokenBalanceService(
    private val users: AppUserRepository,
) {

    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional(readOnly = true)
    fun balanceOf(token: Jwt): TokenBalanceResponse {
        val user = users.findById(ownerId(token))
            .orElseThrow { ResponseStatusException(HttpStatus.FORBIDDEN, "No account behind this token.") }
        return TokenBalanceResponse(user.tokenBalance)
    }

    /**
     * 402 for an affordable-looking request that the balance does not cover, which is
     * a normal answer here rather than a fault: generation-backend is expected to hit
     * it whenever a user runs out mid-session.
     */
    @Transactional
    fun spend(token: Jwt, amount: Int): TokenBalanceResponse {
        val userId = ownerId(token)

        if (users.spendTokens(userId, amount) == 0) {
            // The debit did not happen. Which of the two reasons it was decides the
            // status, and only now is it worth a second query to find out.
            val user = users.findById(userId)
                .orElseThrow { ResponseStatusException(HttpStatus.FORBIDDEN, "No account behind this token.") }
            log.info("Refusing to spend {} tokens for user {}: balance is {}", amount, userId, user.tokenBalance)
            throw ResponseStatusException(HttpStatus.PAYMENT_REQUIRED, "Insufficient token balance.")
        }

        val user = users.findById(userId).orElseThrow()
        log.info("Spent {} tokens for user {}, {} left", amount, userId, user.tokenBalance)
        return TokenBalanceResponse(user.tokenBalance)
    }

    /**
     * The `sub` claim, which [AccessTokenService] stamps with the row id rather than
     * the email precisely so it survives an address being corrected.
     *
     * A subject that is not a UUID cannot be one this application issued, so it is
     * refused rather than allowed to surface as a 500 out of [UUID.fromString].
     */
    private fun ownerId(token: Jwt): UUID =
        try {
            UUID.fromString(token.subject)
        } catch (e: IllegalArgumentException) {
            throw ResponseStatusException(HttpStatus.FORBIDDEN, "Token subject is not a user id.", e)
        }
}

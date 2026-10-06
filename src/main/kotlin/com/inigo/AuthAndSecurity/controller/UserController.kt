package com.inigo.AuthAndSecurity.controller

import com.inigo.AuthAndSecurity.dto.CurrentUser
import com.inigo.AuthAndSecurity.dto.SpendTokensRequest
import com.inigo.AuthAndSecurity.dto.TokenBalanceResponse
import com.inigo.AuthAndSecurity.services.CurrentUserService
import com.inigo.AuthAndSecurity.services.TokenBalanceService
import jakarta.validation.Valid
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Two kinds of caller meet in this class, and they are not authenticated the same way.
 *
 * `/api/user` is for the browser, on the session cookie this application set. The two
 * token endpoints are for generation-backend, on the bearer token `/api/token` handed
 * it — see [SecurityConfig], which puts them on a filter chain of their own so a
 * missing token gets a 401 instead of a redirect to the login page.
 */
@RestController
@RequestMapping("/api")
class UserController(
    private val currentUser: CurrentUserService,
    private val balances: TokenBalanceService,
) {

    /**
     * Reports whichever of the two logins established the session, along with what
     * registration recorded. The endpoint is behind authentication, so an anonymous
     * caller never gets here — the check in [CurrentUser.from] is belt-and-braces in
     * case the rules ever open it up.
     */
    @GetMapping("/user")
    fun user(authentication: Authentication?): CurrentUser = currentUser.of(authentication)

    /**
     * What the holder of this token has left to spend.
     *
     * `hasRole('USER')` the way ImageController over in generation-backend writes its
     * admin checks: the role comes from the `roles` claim, mapped to an authority by
     * the converter in [SecurityConfig]. It is not much of a gate — every registered
     * account has USER — but it is what makes a token minted for a session with no
     * user row behind it fail here rather than halfway down [TokenBalanceService].
     */
    @PreAuthorize("hasRole('USER')")
    @GetMapping(BALANCE_PATH)
    fun balance(@AuthenticationPrincipal token: Jwt): TokenBalanceResponse = balances.balanceOf(token)

    /**
     * Debits the holder's balance, answering 402 when it will not cover the amount.
     *
     * A POST because it changes something, which also keeps the amount out of the
     * query string and so out of the access log.
     */
    @PreAuthorize("hasRole('USER')")
    @PostMapping(SPEND_PATH)
    fun spend(
        @AuthenticationPrincipal token: Jwt,
        @Valid @RequestBody request: SpendTokensRequest,
    ): TokenBalanceResponse = balances.spend(token, request.amount)

    companion object {
        /** Named here and matched in [SecurityConfig], so the two cannot drift apart. */
        const val BALANCE_PATH: String = "/tokens/balance"
        const val SPEND_PATH: String = "/tokens/spend"

        /** The same two as the container sees them, i.e. including this class's `/api`. */
        const val BALANCE_URL: String = "/api$BALANCE_PATH"
        const val SPEND_URL: String = "/api$SPEND_PATH"
    }
}

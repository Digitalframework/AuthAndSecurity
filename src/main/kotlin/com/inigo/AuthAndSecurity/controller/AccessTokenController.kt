package com.inigo.AuthAndSecurity.controller

import com.inigo.AuthAndSecurity.dto.AccessTokenResponse
import com.inigo.AuthAndSecurity.services.AccessTokenService
import com.inigo.AuthAndSecurity.services.AuthenticatedUserResolver
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException

/**
 * Trades the session cookie this application issued for a token another one will
 * accept.
 *
 * That trade is the whole bridge: the cookie is scoped to this host and useless
 * elsewhere, while the token travels in an `Authorization` header and carries its own
 * proof. The browser calls this, then calls generation-backend with what it gets.
 */
@RestController
@RequestMapping("/api")
class AccessTokenController(
    private val resolver: AuthenticatedUserResolver,
    private val tokens: AccessTokenService,
) {

    /**
     * Behind `authenticated`, so an anonymous caller never arrives. A signed-in one
     * still can, without a user-table row: a Google login proves an address and
     * nothing else, and that path never goes through registration. There are no
     * permissions to put in a token for such a session, so it is refused outright
     * rather than handed one claiming nothing — a token that says a user is no-one
     * is worse than no token, because the caller will send it and get a puzzling
     * 403 from the far end instead of a clear one from here.
     */
    @GetMapping("/token")
    fun token(authentication: Authentication?): AccessTokenResponse {
        val user = resolver.resolve(authentication)
            ?: throw ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "This session has no registered account, so no access token can be issued for it",
            )

        return tokens.issueFor(user)
    }
}

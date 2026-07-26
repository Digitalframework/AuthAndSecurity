package com.inigo.AuthAndSecurity.web

import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api")
class UserController {

    /**
     * The principal is null for anonymous callers, which is why this endpoint
     * reports the signed-out case instead of rejecting the request.
     */
    @GetMapping("/me")
    fun me(@AuthenticationPrincipal user: OidcUser?): MeResponse =
        if (user == null) {
            MeResponse(authenticated = false)
        } else {
            MeResponse(
                authenticated = true,
                name = user.fullName,
                email = user.email,
                picture = user.picture,
                subject = user.subject,
            )
        }

    /** Lets the static landing page POST to /logout with a valid CSRF token. */
    @GetMapping("/csrf")
    fun csrf(token: CsrfToken): CsrfResponse =
        CsrfResponse(headerName = token.headerName, token = token.token)
}

data class MeResponse(
    val authenticated: Boolean,
    val name: String? = null,
    val email: String? = null,
    val picture: String? = null,
    val subject: String? = null,
)

data class CsrfResponse(
    val headerName: String,
    val token: String,
)
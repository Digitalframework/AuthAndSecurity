package com.inigo.AuthAndSecurity.onetimetoken

import com.inigo.AuthAndSecurity.services.UserRegistrationService
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler

/**
 * Marks a registration confirmed the moment its token is redeemed, then hands over
 * to the redirect that would have happened anyway.
 *
 * This runs after authentication rather than inside it. Confirming during the
 * lookup in [com.inigo.AuthAndSecurity.services.RegisteredUserDetailsService] would
 * write a row on the strength of a token that had not finished being checked; here
 * the session already exists, so the address is proved before anything is recorded.
 *
 * A token redeemed by someone whose account is already confirmed changes nothing —
 * [UserRegistrationService.complete] is a no-op for them — so the ordinary sign-in
 * path passes through this untouched.
 */
class RegistrationCompletingSuccessHandler(
    private val registrations: UserRegistrationService,
    private val delegate: AuthenticationSuccessHandler = SavedRequestAwareAuthenticationSuccessHandler(),
) : AuthenticationSuccessHandler {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication,
    ) {
        registrations.complete(authentication.name)
        delegate.onAuthenticationSuccess(request, response, authentication)
    }
}

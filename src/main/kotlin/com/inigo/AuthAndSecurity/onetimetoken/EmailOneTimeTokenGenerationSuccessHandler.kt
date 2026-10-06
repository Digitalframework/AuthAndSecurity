package com.inigo.AuthAndSecurity.onetimetoken

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.ott.OneTimeToken
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler
import com.inigo.AuthAndSecurity.services.EmailService
import java.time.Clock
import java.time.Duration

/**
 * Emails the freshly generated token as a sign-in link, then sends the browser to
 * the confirmation page.
 *
 * This is the *sign-in* path only. Registration mints its token through the same
 * service but sends a differently worded message and never passes through here —
 * see [com.inigo.AuthAndSecurity.controller.RegistrationController].
 *
 * Spring Security's own
 * [org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler]
 * only redirects — delivering the token is left to the application, which is what
 * this does.
 */
class EmailOneTimeTokenGenerationSuccessHandler(
    private val emailService: EmailService,
    private val linkBuilder: SignInLinkBuilder,
    private val clock: Clock,
) : OneTimeTokenGenerationSuccessHandler {

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        oneTimeToken: OneTimeToken,
    ) {
        val link = linkBuilder.build(request, oneTimeToken.tokenValue)
        val validFor = Duration.between(clock.instant(), oneTimeToken.expiresAt)

        emailService.sendSignInLink(
            email = oneTimeToken.username,
            link = link,
            token = oneTimeToken.tokenValue,
            validFor = validFor,
        )

        // The same page regardless of address, because the caller is not told
        // whether the mailbox exists — see OneTimeTokenRateLimiter.
        response.sendRedirect(OneTimeTokenRateLimitFilter.SENT_URL)
    }

    companion object {
        /** Matches the login processing URL configured on the DSL. */
        const val SUBMIT_PATH: String = "/login/ott"
    }
}
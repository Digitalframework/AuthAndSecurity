package com.inigo.AuthAndSecurity.onetimetoken

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.ott.OneTimeToken
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler
import com.inigo.AuthAndSecurity.services.EmailService
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Duration

/**
 * Emails the freshly generated token as a sign-in link, then sends the browser to
 * the confirmation page.
 *
 * Spring Security's own
 * [org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler]
 * only redirects — delivering the token is left to the application, which is what
 * this does.
 */
class EmailOneTimeTokenGenerationSuccessHandler(
    private val emailService: EmailService,
    private val properties: OneTimeTokenProperties,
    private val clock: Clock,
) : OneTimeTokenGenerationSuccessHandler {

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        oneTimeToken: OneTimeToken,
    ) {
        val link = buildSignInLink(request, oneTimeToken.tokenValue)
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

    /**
     * Prefers the configured base URL. Falling back to the request is right for
     * local runs, but behind a proxy that does not send forwarded headers it would
     * build a link pointing at an internal hostname the recipient cannot reach —
     * hence `app.ott.base-url`.
     */
    private fun buildSignInLink(request: HttpServletRequest, tokenValue: String): String {
        // The token is base64url, so nothing in it needs escaping; encoding is
        // applied anyway so the link stays correct if the alphabet ever changes.
        val encoded = URLEncoder.encode(tokenValue, StandardCharsets.UTF_8)
        val base = properties.baseUrl?.trimEnd('/') ?: requestBaseUrl(request)
        return "$base$SUBMIT_PATH?token=$encoded"
    }

    private fun requestBaseUrl(request: HttpServletRequest): String {
        val port = request.serverPort
        val defaultPort = (request.scheme == "http" && port == 80) || (request.scheme == "https" && port == 443)
        val authority = if (defaultPort) request.serverName else "${request.serverName}:$port"
        return "${request.scheme}://$authority${request.contextPath}"
    }

    companion object {
        /** Matches the login processing URL configured on the DSL. */
        const val SUBMIT_PATH: String = "/login/ott"
    }
}
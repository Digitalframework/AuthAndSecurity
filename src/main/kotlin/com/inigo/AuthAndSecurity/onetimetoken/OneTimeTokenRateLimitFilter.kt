package com.inigo.AuthAndSecurity.onetimetoken

import com.inigo.AuthAndSecurity.services.LinkPurpose
import com.inigo.AuthAndSecurity.services.LinkRequestDecision
import com.inigo.AuthAndSecurity.services.OneTimeTokenRateLimiterService
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpHeaders
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.web.filter.OncePerRequestFilter

/**
 * Applies [OneTimeTokenRateLimiterService] to the generate endpoint, short-circuiting
 * before Spring Security's
 * [org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter]
 * gets a chance to mint anything.
 *
 * A refusal that must stay silent redirects to the very same confirmation page a
 * success does, so the two are indistinguishable from outside.
 */
class OneTimeTokenRateLimitFilter(
    private val rateLimiter: OneTimeTokenRateLimiterService,
    private val requestMatcher: RequestMatcher,
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response)
            return
        }

        val email = request.getParameter(USERNAME_PARAMETER)
        if (email.isNullOrBlank() || !looksLikeEmail(email)) {
            redirect(response, "$LOGIN_URL?error=email")
            return
        }

        when (val decision = rateLimiter.decide(email, LinkPurpose.SIGN_IN)) {
            LinkRequestDecision.Allowed -> filterChain.doFilter(request, response)

            LinkRequestDecision.SilentlyRefused -> redirect(response, SENT_URL)

            is LinkRequestDecision.TooSoon -> {
                val seconds = decision.retryAfter.seconds.coerceAtLeast(1)
                // Set alongside the redirect rather than on a 429: the caller here
                // is a browser following a form post, and a rendered explanation is
                // more use to it than a status code. The header stays for anything
                // scripted that would rather read it.
                response.setHeader(HttpHeaders.RETRY_AFTER, seconds.toString())
                redirect(response, "$LOGIN_URL?error=throttled&retryAfter=$seconds")
            }

            LinkRequestDecision.QuotaExceeded -> redirect(response, "$LOGIN_URL?error=quota")
        }
    }

    private fun redirect(response: HttpServletResponse, location: String) {
        response.sendRedirect(location)
    }

    /**
     * A shape check, not a validity check — the only thing that really decides
     * whether an address is real is whether the link arrives.
     */
    private fun looksLikeEmail(value: String): Boolean {
        val trimmed = value.trim()
        if (trimmed.length !in 3..254) return false
        val at = trimmed.indexOf('@')
        return at > 0 && at == trimmed.lastIndexOf('@') && at < trimmed.length - 1 && ' ' !in trimmed
    }

    companion object {
        /** The parameter name Spring Security's generate filter reads. */
        const val USERNAME_PARAMETER: String = "username"
        const val LOGIN_URL: String = "/login"
        const val REGISTER_URL: String = "/register"
        const val GENERATE_URL: String = "/ott/generate"
        const val SENT_URL: String = "/ott/sent"
    }
}
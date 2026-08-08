package com.inigo.AuthAndSecurity.onetimetoken

import jakarta.servlet.http.HttpServletRequest
import org.springframework.stereotype.Component
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Turns a freshly minted token into the URL that gets emailed.
 *
 * Shared by the two paths that send one — signing in
 * ([EmailOneTimeTokenGenerationSuccessHandler]) and registering
 * ([com.inigo.AuthAndSecurity.controller.RegistrationController]) — because both
 * links must land on the same page and be built against the same base URL.
 */
@Component
class SignInLinkBuilder(
    private val properties: OneTimeTokenProperties,
) {

    /**
     * Prefers the configured base URL. Falling back to the request is right for
     * local runs, but behind a proxy that does not send forwarded headers it would
     * build a link pointing at an internal hostname the recipient cannot reach —
     * hence `app.ott.base-url`.
     */
    fun build(request: HttpServletRequest, tokenValue: String): String {
        // The token is base64url, so nothing in it needs escaping; encoding is
        // applied anyway so the link stays correct if the alphabet ever changes.
        val encoded = URLEncoder.encode(tokenValue, StandardCharsets.UTF_8)
        val base = properties.baseUrl?.trimEnd('/') ?: requestBaseUrl(request)
        return "$base${EmailOneTimeTokenGenerationSuccessHandler.SUBMIT_PATH}?token=$encoded"
    }

    private fun requestBaseUrl(request: HttpServletRequest): String {
        val port = request.serverPort
        val defaultPort = (request.scheme == "http" && port == 80) || (request.scheme == "https" && port == 443)
        val authority = if (defaultPort) request.serverName else "${request.serverName}:$port"
        return "${request.scheme}://$authority${request.contextPath}"
    }
}

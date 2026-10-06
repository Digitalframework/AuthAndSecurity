package com.inigo.AuthAndSecurity.controller

import com.inigo.AuthAndSecurity.onetimetoken.EmailOneTimeTokenGenerationSuccessHandler
import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenRateLimitFilter
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam

/**
 * The three pages of the sign-in flow. Each is a plain GET; the POSTs that do the
 * work belong to Spring Security's own filters.
 */
@Controller
class LoginPageController {

    /**
     * @param error which refusal to explain, if the rate limiter sent the browser
     *   back here. Deliberately not told apart from "that address does not exist" —
     *   there is no such message, because there is no such answer.
     */
    @GetMapping(OneTimeTokenRateLimitFilter.LOGIN_URL)
    fun login(
        @RequestParam(required = false) error: String?,
        @RequestParam(required = false) retryAfter: Long?,
        model: Model,
    ): String {
        model.addAttribute("message", messageFor(error, retryAfter))
        return "login"
    }

    @GetMapping(OneTimeTokenRateLimitFilter.SENT_URL)
    fun sent(): String = "sent"

    /**
     * Where a sign-in link lands. The token is put into a form rather than spent on
     * arrival, because a GET is followed by link scanners and prefetchers too, and
     * any one of them would burn the token before its owner ever saw the page.
     */
    @GetMapping(EmailOneTimeTokenGenerationSuccessHandler.SUBMIT_PATH)
    fun submit(
        @RequestParam(required = false) token: String?,
        model: Model,
    ): String {
        model.addAttribute("token", token.orEmpty())
        return "ott-submit"
    }

    private fun messageFor(error: String?, retryAfter: Long?): String? = when (error) {
        "email" -> "That does not look like a valid email address."
        "throttled" -> "A link was sent moments ago. Try again in ${retryAfter ?: 60} seconds."
        "quota" -> "Too many links have been requested for that address. Try again later."
        "invalid" -> "That link is not valid or has expired. Request a new one."
        else -> null
    }
}
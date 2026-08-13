package com.inigo.AuthAndSecurity.controller

import com.inigo.AuthAndSecurity.payment.PaypalException
import com.inigo.AuthAndSecurity.payment.TokenPack
import com.inigo.AuthAndSecurity.services.PaymentResult
import com.inigo.AuthAndSecurity.services.PaypalService
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam

/**
 * The three URLs the PayPal round trip needs: one to leave by, two to come back
 * through.
 *
 * All are behind the default `authenticated()` rule, including the return leg.
 * That the session survives the trip is not luck: session cookies default to
 * `SameSite=Lax`, and a top-level GET navigation is exactly the case `Lax` still
 * sends them on. Were the return a POST, it would arrive signed out.
 */
@Controller
@RequestMapping("/paypal")
class PaypalController(
    private val paypal: PaypalService,
) {

    private val log = LoggerFactory.getLogger(javaClass)

    /**
     * A POST because it creates something, which also means CSRF applies —
     * otherwise any page could open orders in a signed-in visitor's name. The
     * redirect target is the approval link PayPal just returned over the API, not
     * anything off the request, so this is not an open redirect.
     */
    @PostMapping("/create")
    fun create(
        authentication: Authentication?,
        @RequestParam pack: TokenPack,
        request: HttpServletRequest,
    ): String = "redirect:${paypal.createPayment(authentication, pack, request)}"

    @GetMapping("/success")
    fun success(
        authentication: Authentication?,
        @RequestParam("token") orderId: String,
    ): String = when (paypal.executePayment(authentication, orderId)) {
        PaymentResult.CREDITED -> "redirect:/?purchase=ok"
        PaymentResult.ALREADY_CREDITED -> "redirect:/?purchase=already"
        PaymentResult.NOT_APPROVED -> "redirect:/?purchase=unapproved"
    }

    /** Backing out opens nothing that needs undoing. */
    @GetMapping("/cancel")
    fun cancel(): String = "redirect:/?purchase=cancelled"

    /** PayPal being unreachable or misconfigured is for the log, not for a stack trace on screen. */
    @ExceptionHandler(PaypalException::class)
    fun payPalUnavailable(e: PaypalException): String {
        log.error("PayPal call failed", e)
        return "redirect:/?purchase=error"
    }
}

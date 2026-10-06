package com.inigo.AuthAndSecurity.controller

import com.inigo.AuthAndSecurity.payment.PaypalProperties
import com.inigo.AuthAndSecurity.payment.TokenPack
import com.inigo.AuthAndSecurity.services.CurrentUserService
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam

/**
 * The page behind the login. Reaching it at all means a session exists, so there
 * is no signed-out branch to render.
 */
@Controller
class HomeController(
    private val currentUser: CurrentUserService,
    private val paypal: PaypalProperties,
) {

    /**
     * @param purchase how a trip to PayPal ended, put there by the redirect
     *   [PaypalController] answers with. Only ever picks a message — the balance is
     *   read from the user table like everything else here, so a hand-edited
     *   `?purchase=ok` shows a line of text and changes nothing.
     */
    @GetMapping("/")
    fun home(
        authentication: Authentication?,
        @RequestParam(required = false) purchase: String?,
        model: Model,
    ): String {
        model.addAttribute("user", currentUser.of(authentication))
        model.addAttribute("packs", TokenPack.entries)
        model.addAttribute("currency", paypal.currency)
        model.addAttribute("payPalEnabled", paypal.configured)
        model.addAttribute("purchase", purchase)
        return "home"
    }
}

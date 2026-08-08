package com.inigo.AuthAndSecurity.controller

import com.inigo.AuthAndSecurity.services.CurrentUserService
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping

/**
 * The page behind the login. Reaching it at all means a session exists, so there
 * is no signed-out branch to render.
 */
@Controller
class HomeController(
    private val currentUser: CurrentUserService,
) {

    @GetMapping("/")
    fun home(authentication: Authentication?, model: Model): String {
        model.addAttribute("user", currentUser.of(authentication))
        return "home"
    }
}
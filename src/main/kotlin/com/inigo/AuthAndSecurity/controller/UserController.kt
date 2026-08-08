package com.inigo.AuthAndSecurity.controller

import com.inigo.AuthAndSecurity.dto.CurrentUser
import com.inigo.AuthAndSecurity.services.CurrentUserService
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api")
class UserController(
    private val currentUser: CurrentUserService,
) {

    /**
     * Reports whichever of the two logins established the session, along with what
     * registration recorded. The endpoint is behind authentication, so an anonymous
     * caller never gets here — the check in [CurrentUser.from] is belt-and-braces in
     * case the rules ever open it up.
     */
    @GetMapping("/user")
    fun user(authentication: Authentication?): CurrentUser = currentUser.of(authentication)
}

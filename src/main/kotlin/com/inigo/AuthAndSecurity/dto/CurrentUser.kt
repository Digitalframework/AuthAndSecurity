package com.inigo.AuthAndSecurity.dto

import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser

/**
 * The signed-in user as the API and the templates see them. Serves both `/api/user`
 * and the `user` model attribute on the home page, which is why it is not named
 * after either one.
 */
data class CurrentUser(
    val authenticated: Boolean,
    /** `"google"` or `"email"`, absent when nobody is signed in. */
    val method: String? = null,
    val name: String? = null,
    val email: String? = null,
    val picture: String? = null,
    val subject: String? = null,
) {
    companion object {

        fun from(authentication: Authentication?): CurrentUser {
            if (authentication == null ||
                authentication is AnonymousAuthenticationToken ||
                !authentication.isAuthenticated
            ) {
                return CurrentUser(authenticated = false)
            }
            return when (val principal = authentication.principal) {
                is OidcUser -> CurrentUser(
                    authenticated = true,
                    method = "google",
                    name = principal.fullName,
                    email = principal.email,
                    picture = principal.picture,
                    subject = principal.subject,
                )
                // A redeemed sign-in link proves control of the mailbox and nothing
                // else, so the address is the whole of the profile.
                else -> CurrentUser(
                    authenticated = true,
                    method = "email",
                    email = authentication.name,
                    subject = authentication.name,
                )
            }
        }
    }
}

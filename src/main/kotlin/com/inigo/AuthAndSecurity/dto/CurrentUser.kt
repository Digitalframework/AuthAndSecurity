package com.inigo.AuthAndSecurity.dto

import com.inigo.AuthAndSecurity.entity.AppUser
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import java.time.LocalDate

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

    // What registration collected. Null for a session with no row behind it, which
    // a Google login can be: that path does not go through registration.
    val firstname: String? = null,
    val surname: String? = null,
    val dateOfBirth: LocalDate? = null,
    val permissions: List<String> = emptyList(),
) {
    companion object {

        /**
         * @param profile the user table row for this session, when there is one.
         *   Looked up by the caller — see
         *   [com.inigo.AuthAndSecurity.services.CurrentUserService] — because this
         *   is a plain value type with nothing to query with.
         */
        fun from(authentication: Authentication?, profile: AppUser? = null): CurrentUser {
            if (authentication == null ||
                authentication is AnonymousAuthenticationToken ||
                !authentication.isAuthenticated
            ) {
                return CurrentUser(authenticated = false)
            }

            val registered = profile?.let { user ->
                CurrentUser(
                    authenticated = true,
                    firstname = user.firstname,
                    surname = user.surname,
                    dateOfBirth = user.dateOfBirth,
                    permissions = user.permissions.map { it.name }.sorted(),
                )
            } ?: CurrentUser(authenticated = true)

            return when (val principal = authentication.principal) {
                is OidcUser -> registered.copy(
                    method = "google",
                    name = principal.fullName,
                    email = principal.email,
                    picture = principal.picture,
                    subject = principal.subject,
                )
                // A redeemed sign-in link proves control of the mailbox, so the
                // address is all the session itself carries; anything more shown
                // here came out of the user table.
                else -> registered.copy(
                    method = "email",
                    name = profile?.let { "${it.firstname} ${it.surname}".trim() },
                    email = authentication.name,
                    subject = authentication.name,
                )
            }
        }
    }
}

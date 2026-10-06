package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.entity.AppUser
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import java.util.Locale

/**
 * Maps a session back to the user-table row behind it — the one thing neither
 * login puts straight into the principal: an emailed link's session carries only
 * an address, and a Google session carries a Google profile with no idea this
 * table exists.
 *
 * Shared by [CurrentUserService] and [UserImagesService], both of which need
 * the same [AppUser.userId] the session is standing in for.
 */
@Component
class AuthenticatedUserResolver(
    private val users: AppUserRepository,
) {

    /**
     * `null` covers both an anonymous caller and a Google sign-in by someone who
     * never registered here — that login proves an email address too, just not
     * one this table has a row for.
     */
    @Transactional(readOnly = true)
    fun resolve(authentication: Authentication?): AppUser? {
        if (authentication == null) return null

        val email = when (val principal = authentication.principal) {
            is OidcUser -> principal.email
            else -> authentication.name
        } ?: return null

        return users.findByEmail(email.trim().lowercase(Locale.ROOT))
    }
}

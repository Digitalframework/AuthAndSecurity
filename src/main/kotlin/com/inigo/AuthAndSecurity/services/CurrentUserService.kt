package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.dto.CurrentUser
import com.inigo.AuthAndSecurity.entity.AppUser
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.Locale

/**
 * Puts the registered details behind a session, for the pages and the API that
 * show them.
 *
 * The session itself only ever carries an email address — that is all a redeemed
 * token proves — so name, age and permissions have to be read back out of the user
 * table on each request rather than parked in the principal, where they would go
 * stale the moment a row changed.
 */
@Service
class CurrentUserService(
    private val users: AppUserRepository,
) {

    @Transactional(readOnly = true)
    fun of(authentication: Authentication?): CurrentUser =
        CurrentUser.from(authentication, profileFor(authentication))

    /**
     * A Google sign-in has no row unless that person also registered here, which is
     * why this may come back null for a perfectly valid session.
     */
    private fun profileFor(authentication: Authentication?): AppUser? {
        val email = when (val principal = authentication?.principal) {
            null -> null
            is OidcUser -> principal.email
            else -> authentication.name
        } ?: return null

        return users.findByEmail(email.trim().lowercase(Locale.ROOT))
    }
}

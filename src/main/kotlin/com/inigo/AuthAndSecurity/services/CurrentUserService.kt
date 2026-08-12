package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.dto.CurrentUser
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Service

/**
 * Puts the registered details behind a session, for the pages and the API that
 * show them.
 *
 * The session itself only ever carries an email address — that is all a redeemed
 * token proves — so name, date of birth and permissions have to be read back out
 * of the user table on each request rather than parked in the principal, where
 * they would go stale the moment a row changed. [AuthenticatedUserResolver] is
 * what does that lookup.
 */
@Service
class CurrentUserService(
    private val resolver: AuthenticatedUserResolver,
) {

    fun of(authentication: Authentication?): CurrentUser =
        CurrentUser.from(authentication, resolver.resolve(authentication))
}

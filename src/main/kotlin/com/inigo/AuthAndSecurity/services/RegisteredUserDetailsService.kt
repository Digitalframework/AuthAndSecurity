package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenProperties
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.Locale

/**
 * Resolves the address a redeemed token was issued to into a principal, out of the
 * user table.
 *
 * `username` here is the email address — [PersistentOneTimeTokenService] normalizes
 * it before storing, and it arrives back from the redeemed token row rather than
 * from anything the caller typed.
 *
 * Unconfirmed rows are accepted, which looks like a hole and is not: redeeming the
 * token *is* the confirmation, so refusing them here would leave every registration
 * permanently unable to complete. The flip happens immediately afterwards, in
 * [com.inigo.AuthAndSecurity.onetimetoken.RegistrationCompletingSuccessHandler]. What
 * stops an unconfirmed row being used as an account in the meantime is that no
 * *sign-in* link is ever issued for one — see [OneTimeTokenRateLimiterService].
 *
 * The allowlist is re-checked here even though [OneTimeTokenRateLimiterService] already
 * checked it at generation time. The two run minutes apart, and an address removed
 * from the list in between must not still be able to spend a link that was already
 * in its inbox.
 */
@Service
class RegisteredUserDetailsService(
    private val users: AppUserRepository,
    private val properties: OneTimeTokenProperties,
) : UserDetailsService {

    @Transactional(readOnly = true)
    override fun loadUserByUsername(username: String): UserDetails {
        val email = username.trim().lowercase(Locale.ROOT)

        // Unlike the generate endpoint, this one may speak plainly: reaching it
        // requires already holding a valid token for the address, so a caller who
        // gets this far has learned nothing they did not already know.
        if (!properties.allows(email)) {
            throw UsernameNotFoundException("$email is not allowed to sign in")
        }

        val user = users.findByEmail(email)
            ?: throw UsernameNotFoundException("$email has not registered")

        return User.withUsername(user.email)
            // Nothing ever authenticates by password here. An unencoded placeholder
            // would be a password of "", so a value no encoder will match is used
            // instead, and the field is erased after authentication regardless.
            .password(UNUSABLE_PASSWORD)
            .authorities(user.permissions.map { it.authority })
            .build()
    }

    private companion object {
        /**
         * The `{noop}`-less, algorithm-less form deliberately fails
         * `DelegatingPasswordEncoder`, which is what makes it unusable rather than
         * merely unknown.
         */
        const val UNUSABLE_PASSWORD: String = "unusable-no-password-login"
    }
}

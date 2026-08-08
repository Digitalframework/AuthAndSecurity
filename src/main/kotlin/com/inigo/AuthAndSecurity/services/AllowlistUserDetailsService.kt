package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenProperties
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import java.util.Locale

/**
 * Resolves the address a redeemed token was issued to into a principal.
 *
 * There is no user table behind this, and that is the design rather than an
 * omission: holding a sign-in link proves control of a mailbox, and that is the
 * whole of what this login claims. So every allowlisted address resolves to the
 * same shape of principal, created on the spot and never stored.
 *
 * `username` here is the email address — [PersistentOneTimeTokenService] normalizes
 * it before storing, and it arrives back from the redeemed token row rather than
 * from anything the caller typed.
 *
 * The allowlist is re-checked here even though [OneTimeTokenRateLimiterService] already
 * checked it at generation time. The two run minutes apart, and an address removed
 * from the list in between must not still be able to spend a link that was already
 * in its inbox.
 */
@Service
class AllowlistUserDetailsService(
    private val properties: OneTimeTokenProperties,
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val email = username.trim().lowercase(Locale.ROOT)

        // Unlike the generate endpoint, this one may speak plainly: reaching it
        // requires already holding a valid token for the address, so a caller who
        // gets this far has learned nothing they did not already know.
        if (!properties.allows(email)) {
            throw UsernameNotFoundException("$email is not allowed to sign in")
        }

        return User.withUsername(email)
            // Nothing ever authenticates by password here. An unencoded placeholder
            // would be a password of "", so a value no encoder will match is used
            // instead, and the field is erased after authentication regardless.
            .password(UNUSABLE_PASSWORD)
            .authorities(AuthorityUtils.createAuthorityList("ROLE_USER"))
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
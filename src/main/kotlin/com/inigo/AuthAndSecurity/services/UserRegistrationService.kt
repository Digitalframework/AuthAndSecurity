package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.dto.RegistrationForm
import com.inigo.AuthAndSecurity.entity.AppUser
import com.inigo.AuthAndSecurity.entity.Permission
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.util.Locale

/** What submitting the registration form did to the user table. */
sealed interface RegistrationOutcome {

    /**
     * A row is waiting to be confirmed — either brand new, or an earlier
     * unconfirmed attempt whose details were overwritten by this one. The caller
     * emails a verification link.
     */
    data class AwaitingVerification(val firstname: String) : RegistrationOutcome

    /**
     * That address already belongs to a confirmed account, so nothing was written.
     * The details submitted are discarded rather than applied: whoever filled the
     * form in has not proved they own the address, and letting them through would
     * mean anyone could rewrite a stranger's details by registering it again.
     *
     * The caller still sends mail — an ordinary sign-in link — so that the page
     * cannot be used to find out which addresses are taken.
     */
    data object AlreadyRegistered : RegistrationOutcome
}

/**
 * Owns the user table: who gets a row, when it counts as confirmed, and what they
 * are allowed to do.
 *
 * Registration is two steps by design. Submitting the form only writes an
 * unconfirmed row; the account does not exist as far as signing in is concerned
 * until the emailed token comes back, which is what proves the address belongs to
 * whoever filled the form in. [complete] is the moment that flips.
 */
@Service
class UserRegistrationService(
    private val users: AppUserRepository,
    private val clock: Clock,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional
    fun start(form: RegistrationForm): RegistrationOutcome {
        val email = normalizeEmail(form.email)
        // Validated as @NotNull on the form, so the binder has already rejected a
        // request that omits it before anything reaches here.
        val dateOfBirth = requireNotNull(form.dateOfBirth) { "the form must be validated before it gets here" }

        val existing = users.findByEmail(email)
        if (existing != null && existing.verified) {
            log.info("Registration for {} ignored: that address is already confirmed", email)
            return RegistrationOutcome.AlreadyRegistered
        }

        if (existing == null) {
            users.save(
                AppUser(
                    email = email,
                    firstname = form.firstname.trim(),
                    surname = form.surname.trim(),
                    dateOfBirth = dateOfBirth,
                    // The form cannot ask for either of these, and nothing here
                    // reads them back off the request: the permissions are fixed,
                    // and the token balance is left to its default rather than
                    // being passed in at all.
                    permissions = mutableSetOf(Permission.USER),
                    createdAt = clock.instant(),
                )
            )
            log.info("Registration started for {}", email)
        } else {
            // An unconfirmed row, so this is a second go at the same registration —
            // a typo in the surname, say. Overwriting is safe precisely because
            // nothing has been proved about the old attempt either.
            existing.firstname = form.firstname.trim()
            existing.surname = form.surname.trim()
            existing.dateOfBirth = dateOfBirth
            users.save(existing)
            log.info("Registration restarted for {}", email)
        }

        return RegistrationOutcome.AwaitingVerification(form.firstname.trim())
    }

    /**
     * Confirms the registration behind [rawEmail], if there is an unconfirmed one.
     * Called once the token has been redeemed, so reaching here is itself the proof
     * that the address was real.
     *
     * Returns whether this call is what confirmed it; `false` covers both an
     * account that was already confirmed and a sign-in by someone who never
     * registered through this application at all, such as a Google login.
     */
    @Transactional
    fun complete(rawEmail: String): Boolean {
        val email = normalizeEmail(rawEmail)
        val user = users.findByEmail(email) ?: return false
        if (user.verified) return false

        user.verifiedAt = clock.instant()
        users.save(user)
        log.info("Registration confirmed for {}", email)
        return true
    }

    private fun normalizeEmail(rawEmail: String): String = rawEmail.trim().lowercase(Locale.ROOT)
}

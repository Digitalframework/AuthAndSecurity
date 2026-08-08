package com.inigo.AuthAndSecurity.controller

import com.inigo.AuthAndSecurity.dto.RegistrationForm
import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenProperties
import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenRateLimitFilter
import com.inigo.AuthAndSecurity.onetimetoken.SignInLinkBuilder
import com.inigo.AuthAndSecurity.services.EmailService
import com.inigo.AuthAndSecurity.services.LinkPurpose
import com.inigo.AuthAndSecurity.services.LinkRequestDecision
import com.inigo.AuthAndSecurity.services.OneTimeTokenRateLimiterService
import com.inigo.AuthAndSecurity.services.PersistentOneTimeTokenService
import com.inigo.AuthAndSecurity.services.RegistrationOutcome
import com.inigo.AuthAndSecurity.services.UserRegistrationService
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import jakarta.validation.Valid
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.validation.BindingResult
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ModelAttribute
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import java.time.Clock
import java.time.LocalDate
import java.time.Period
import java.util.Locale

/**
 * Signing up: collect the details, then email a token that has to come back before
 * the account counts as real.
 *
 * The token itself is the same kind the sign-in page issues, minted by the same
 * service and redeemed at the same URL, so the whole of the redemption path —
 * hashing, expiry, single use, rate limits — is shared rather than reimplemented
 * for registration. What differs is only what happens on either side of it: this
 * page writes an unconfirmed row first, and
 * [com.inigo.AuthAndSecurity.onetimetoken.RegistrationCompletingSuccessHandler]
 * confirms it after.
 */
@Controller
class RegistrationController(
    private val registrations: UserRegistrationService,
    private val rateLimiter: OneTimeTokenRateLimiterService,
    private val tokenService: PersistentOneTimeTokenService,
    private val emailService: EmailService,
    private val linkBuilder: SignInLinkBuilder,
    private val properties: OneTimeTokenProperties,
    private val clock: Clock,
) {

    @GetMapping(OneTimeTokenRateLimitFilter.REGISTER_URL)
    fun form(
        @RequestParam(required = false) error: String?,
        @RequestParam(required = false) retryAfter: Long?,
        model: Model,
    ): String {
        model.addAttribute("message", messageFor(error, retryAfter))
        model.addAttribute(FORM_ATTRIBUTE, RegistrationForm())
        return "register"
    }

    /**
     * Answers identically whether or not the address is already taken, so the form
     * cannot be used to work out who has an account here. Both paths send mail and
     * both land on the same confirmation page; which of the two messages goes out
     * is only visible to whoever can read that mailbox.
     */
    @PostMapping(OneTimeTokenRateLimitFilter.REGISTER_URL)
    fun register(
        @Valid @ModelAttribute(FORM_ATTRIBUTE) form: RegistrationForm,
        binding: BindingResult,
        request: HttpServletRequest,
        response: HttpServletResponse,
    ): String {
        // Rendered rather than redirected, so the fields the visitor already filled
        // in survive alongside the messages against them.
        if (binding.hasErrors()) return "register"

        // Not a bean-validation annotation on the form because the boundary moves
        // with the calendar: pinning it to a fixed date would need editing every
        // year, and stamping it in at class-load time would drift the moment the
        // application had been running across a birthday.
        form.dateOfBirth?.let { dateOfBirth ->
            val age = Period.between(dateOfBirth, LocalDate.now(clock)).years
            if (age < MINIMUM_AGE) {
                binding.rejectValue("dateOfBirth", "age.min", "You must be at least $MINIMUM_AGE to register.")
                return "register"
            }
        }

        val email = form.email.trim().lowercase(Locale.ROOT)

        // Ahead of any write: a refused request must leave no row behind, exactly
        // as a refused sign-in leaves no token behind.
        when (val decision = rateLimiter.decide(email, LinkPurpose.REGISTRATION)) {
            LinkRequestDecision.Allowed -> Unit

            LinkRequestDecision.SilentlyRefused -> return "redirect:${OneTimeTokenRateLimitFilter.SENT_URL}"

            is LinkRequestDecision.TooSoon -> {
                val seconds = decision.retryAfter.seconds.coerceAtLeast(1)
                response.setHeader(HttpHeaders.RETRY_AFTER, seconds.toString())
                return "redirect:$REGISTER_URL?error=throttled&retryAfter=$seconds"
            }

            LinkRequestDecision.QuotaExceeded -> return "redirect:$REGISTER_URL?error=quota"
        }

        val outcome = registrations.start(form)

        val token = tokenService.generate(GenerateOneTimeTokenRequest(email, properties.ttl))
        val link = linkBuilder.build(request, token.tokenValue)
        when (outcome) {
            is RegistrationOutcome.AwaitingVerification -> emailService.sendVerificationLink(
                email = email,
                firstname = outcome.firstname,
                link = link,
                token = token.tokenValue,
                validFor = properties.ttl,
            )
            // Nothing was written, so this is just a way in for someone who forgot
            // they had already signed up. The wording is the sign-in one because
            // that is all the link does for them.
            RegistrationOutcome.AlreadyRegistered -> emailService.sendSignInLink(
                email = email,
                link = link,
                token = token.tokenValue,
                validFor = properties.ttl,
            )
        }

        return "redirect:${OneTimeTokenRateLimitFilter.SENT_URL}"
    }

    private fun messageFor(error: String?, retryAfter: Long?): String? = when (error) {
        "throttled" -> "A link was sent moments ago. Try again in ${retryAfter ?: 60} seconds."
        "quota" -> "Too many links have been requested for that address. Try again later."
        else -> null
    }

    private companion object {
        const val FORM_ATTRIBUTE: String = "form"
        const val REGISTER_URL: String = OneTimeTokenRateLimitFilter.REGISTER_URL
        const val MINIMUM_AGE: Int = 16
    }
}

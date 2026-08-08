package com.inigo.AuthAndSecurity.dto

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Past
import jakarta.validation.constraints.Size
import java.time.LocalDate

/**
 * What the registration page collects. Every field has a default so Thymeleaf can
 * bind an empty instance onto a freshly rendered form, and every one is a `var`
 * because the binder writes into it.
 *
 * The minimum-age check (16 years old) is not a bean-validation annotation, since
 * that would have to be pinned to a fixed date: see
 * [com.inigo.AuthAndSecurity.controller.RegistrationController.register], which
 * checks it against the clock instead.
 *
 * The permissions a user ends up with are not here on purpose: they are decided by
 * [com.inigo.AuthAndSecurity.services.UserRegistrationService], never by the form,
 * or registering as an administrator would be a matter of adding a field to the
 * POST.
 */
data class RegistrationForm(

    @field:NotBlank(message = "An email address is required.")
    @field:Email(message = "That does not look like a valid email address.")
    @field:Size(max = 254, message = "That email address is too long.")
    var email: String = "",

    @field:NotBlank(message = "A first name is required.")
    @field:Size(max = 100, message = "That first name is too long.")
    var firstname: String = "",

    @field:NotBlank(message = "A surname is required.")
    @field:Size(max = 100, message = "That surname is too long.")
    var surname: String = "",

    @field:NotNull(message = "A date of birth is required.")
    @field:Past(message = "That date of birth has not happened yet.")
    var dateOfBirth: LocalDate? = null,
)

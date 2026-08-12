package com.inigo.AuthAndSecurity.dto

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.web.multipart.MultipartFile

/**
 * A saved furniture entry as the multipart form submits it.
 *
 * [picture] is not `@NotNull`: it is required on create and optional on update
 * (an update that omits it keeps the picture already on file), and only
 * [com.inigo.AuthAndSecurity.services.UserImagesService] knows which of the
 * two cases applies, so it is what enforces that rather than a bean-validation
 * annotation here.
 */
data class UserImagesForm(

    @field:NotBlank(message = "A style is required.")
    @field:Size(max = 100, message = "That style name is too long.")
    var style: String = "",

    var favorite: Boolean = false,

    var picture: MultipartFile? = null,
)

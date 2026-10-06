package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.dto.UserImagesForm
import com.inigo.AuthAndSecurity.dto.UserImagesResponse
import com.inigo.AuthAndSecurity.entity.UserImages
import com.inigo.AuthAndSecurity.repositories.UserImagesRepository
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.transaction.annotation.Transactional
import org.springframework.validation.BindingResult
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ModelAttribute
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.multipart.MultipartFile
import org.springframework.web.server.ResponseStatusException
import java.io.ByteArrayInputStream
import java.util.UUID
import javax.imageio.ImageIO

/**
 * Saved furniture pictures: the endpoints and the rules behind them, in one
 * class.
 *
 * There is deliberately no separate controller. The layer that would have sat in
 * front of this held nothing but the HTTP mapping and a call straight through,
 * and the rules it would have delegated to — the 1024x1024 check, the ownership
 * scoping — were already expressed in terms of HTTP status codes here, so the
 * split was notional rather than real. Collapsing the two puts the transaction
 * boundary and the request boundary on the same method, which is what they always
 * were.
 *
 * Every endpoint resolves the caller's own user id through
 * [AuthenticatedUserResolver] and scopes every query to it — an owner id is never
 * taken from the path or the body — so there is no way to reach another visitor's
 * row from here. A lookup against someone else's id finds nothing and answers 404,
 * the same as an id that was never real, rather than a 403 that would confirm it
 * exists.
 *
 * Reachable only by an authenticated session: nothing here is listed as
 * `permitAll` in `SecurityConfig`, so the default `authenticated()` rule already
 * covers every path under `/api/user-preferences`.
 */
@RestController
@RequestMapping("/api/user-preferences")
class UserImagesService(
    private val preferences: UserImagesRepository,
    private val userResolver: AuthenticatedUserResolver,
) {

    @GetMapping
    @Transactional(readOnly = true)
    fun list(authentication: Authentication?): List<UserImagesResponse> =
        preferences.findAllByUserId(ownerId(authentication)).map { it.toResponse() }

    @GetMapping("/{id}")
    @Transactional(readOnly = true)
    fun get(authentication: Authentication?, @PathVariable id: UUID): UserImagesResponse =
        findOwned(ownerId(authentication), id).toResponse()

    @GetMapping("/{id}/picture")
    @Transactional(readOnly = true)
    fun picture(authentication: Authentication?, @PathVariable id: UUID): ResponseEntity<ByteArray> {
        val saved = findOwned(ownerId(authentication), id)
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(saved.pictureContentType))
            .body(saved.savedPicture)
    }

    @PostMapping(consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    fun create(
        authentication: Authentication?,
        @Valid @ModelAttribute form: UserImagesForm,
        binding: BindingResult,
    ): UserImagesResponse {
        rejectIfInvalid(binding)
        val userId = ownerId(authentication)

        val picture = form.picture?.takeIf { !it.isEmpty }
            ?: throw ResponseStatusException(HttpStatus.BAD_REQUEST, "A picture is required.")
        val (bytes, contentType) = readAndValidatePicture(picture)

        return preferences.save(
            UserImages(
                userId = userId,
                savedPicture = bytes,
                pictureContentType = contentType,
                style = form.style.trim(),
                favorite = form.favorite,
            )
        ).toResponse()
    }

    /** A full replace of every field but the picture, which stays optional — see [UserImagesForm]. */
    @PutMapping("/{id}", consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
    @Transactional
    fun update(
        authentication: Authentication?,
        @PathVariable id: UUID,
        @Valid @ModelAttribute form: UserImagesForm,
        binding: BindingResult,
    ): UserImagesResponse {
        rejectIfInvalid(binding)
        val existing = findOwned(ownerId(authentication), id)

        // Optional here — see UserImagesForm — so an update that leaves the
        // field off the request keeps whatever picture is already on file.
        form.picture?.takeIf { !it.isEmpty }?.let {
            val (bytes, contentType) = readAndValidatePicture(it)
            existing.savedPicture = bytes
            existing.pictureContentType = contentType
        }
        existing.style = form.style.trim()
        existing.favorite = form.favorite

        return preferences.save(existing).toResponse()
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    fun delete(authentication: Authentication?, @PathVariable id: UUID) {
        if (preferences.deleteByPreferenceIdAndUserId(id, ownerId(authentication)) == 0L) {
            throw ResponseStatusException(HttpStatus.NOT_FOUND)
        }
    }

    /**
     * Only a session backed by a confirmed registration gets an id at all: a
     * Google-only sign-in with no row in `app_user` has nothing to own preferences
     * against, so it is refused rather than resolved to some fallback id.
     */
    private fun ownerId(authentication: Authentication?): UUID =
        userResolver.resolve(authentication)?.userId
            ?: throw ResponseStatusException(HttpStatus.FORBIDDEN, "No registered account behind this session.")

    /** The only way a row is ever loaded here, so the ownership scoping cannot be skipped. */
    private fun findOwned(userId: UUID, id: UUID): UserImages =
        preferences.findByPreferenceIdAndUserId(id, userId)
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND)

    /**
     * Rejects anything that is not a readable image, or not exactly 1024x1024 —
     * the fixed size every saved picture is expected to be. Read via ImageIO
     * rather than trusting the declared content type, since that header is just
     * whatever the caller's browser sent.
     */
    private fun readAndValidatePicture(file: MultipartFile): Pair<ByteArray, String> {
        val contentType = file.contentType
        if (contentType == null || !contentType.startsWith("image/")) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "The picture must be an image file.")
        }

        val bytes = file.bytes
        val image = ImageIO.read(ByteArrayInputStream(bytes))
            ?: throw ResponseStatusException(HttpStatus.BAD_REQUEST, "That file is not a readable image.")
        if (image.width != REQUIRED_DIMENSION || image.height != REQUIRED_DIMENSION) {
            throw ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "The picture must be exactly ${REQUIRED_DIMENSION}x$REQUIRED_DIMENSION pixels, " +
                    "was ${image.width}x${image.height}.",
            )
        }

        return bytes to contentType
    }

    private fun rejectIfInvalid(binding: BindingResult) {
        if (binding.hasErrors()) {
            val message = binding.allErrors.firstOrNull()?.defaultMessage ?: "Invalid request."
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, message)
        }
    }

    private fun UserImages.toResponse() = UserImagesResponse(
        id = requireNotNull(preferenceId),
        style = style,
        favorite = favorite,
        pictureUrl = "/api/user-preferences/$preferenceId/picture",
    )

    private companion object {
        const val REQUIRED_DIMENSION = 1024
    }
}

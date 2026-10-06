package com.inigo.AuthAndSecurity.preferences

import com.inigo.AuthAndSecurity.entity.AppUser
import com.inigo.AuthAndSecurity.entity.UserImages
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import com.inigo.AuthAndSecurity.repositories.UserImagesRepository
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.HttpMethod
import org.springframework.mock.web.MockMultipartFile
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.time.Instant
import java.time.LocalDate
import java.util.UUID
import javax.imageio.ImageIO
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@SpringBootTest(
    properties = [
        "spring.security.oauth2.client.registration.google.client-id=test-client-id",
        "spring.security.oauth2.client.registration.google.client-secret=test-client-secret",
    ]
)
@AutoConfigureMockMvc
class UserImagesEndpointsTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var users: AppUserRepository

    @Autowired
    private lateinit var preferences: UserImagesRepository

    private lateinit var owner: AppUser

    @BeforeEach
    fun setUp() {
        preferences.deleteAll()
        users.deleteAll()
        owner = registerUser("sam@example.com")
    }

    private fun registerUser(email: String): AppUser = users.save(
        AppUser(
            email = email,
            firstname = "Sam",
            surname = "Example",
            dateOfBirth = LocalDate.of(1995, 1, 1),
            createdAt = Instant.now(),
            verifiedAt = Instant.now(),
        )
    )

    /** A minimal, valid PNG of the given size — real bytes, not a stub. */
    private fun square(size: Int): ByteArray {
        val image = BufferedImage(size, size, BufferedImage.TYPE_INT_RGB)
        val out = ByteArrayOutputStream()
        ImageIO.write(image, "png", out)
        return out.toByteArray()
    }

    private fun picture(size: Int = 1024) = MockMultipartFile("picture", "chair.png", "image/png", square(size))

    @Test
    fun `creates a preference with a valid picture`() {
        mockMvc.perform(
            multipart("/api/user-preferences")
                .file(picture())
                .param("style", "Scandinavian")
                .param("favorite", "true")
                .with(csrf())
                .with(user("sam@example.com").roles("USER"))
        )
            .andExpect(status().isCreated)
            .andExpect(jsonPath("$.style").value("Scandinavian"))
            .andExpect(jsonPath("$.favorite").value(true))
            .andExpect(jsonPath("$.pictureUrl").exists())

        val saved = preferences.findAllByUserId(requireNotNull(owner.userId)).single()
        assertEquals("image/png", saved.pictureContentType)
        assertTrue(saved.savedPicture.isNotEmpty())
    }

    @Test
    fun `rejects a picture that is not 1024x1024`() {
        mockMvc.perform(
            multipart("/api/user-preferences")
                .file(picture(size = 512))
                .param("style", "Scandinavian")
                .with(csrf())
                .with(user("sam@example.com").roles("USER"))
        ).andExpect(status().isBadRequest)

        assertTrue(preferences.findAll().isEmpty(), "a rejected picture must leave no row behind")
    }

    @Test
    fun `rejects a submission with no picture`() {
        mockMvc.perform(
            multipart("/api/user-preferences")
                .param("style", "Scandinavian")
                .with(csrf())
                .with(user("sam@example.com").roles("USER"))
        ).andExpect(status().isBadRequest)
    }

    @Test
    fun `lists only the caller's own preferences`() {
        val stranger = registerUser("alex@example.com")
        preferences.save(preferenceFor(stranger.userId!!))
        preferences.save(preferenceFor(owner.userId!!))

        mockMvc.perform(get("/api/user-preferences").with(user("sam@example.com").roles("USER")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.length()").value(1))
    }

    @Test
    fun `a visitor cannot read another visitor's preference`() {
        val stranger = registerUser("alex@example.com")
        val saved = preferences.save(preferenceFor(stranger.userId!!))

        mockMvc.perform(
            get("/api/user-preferences/${saved.preferenceId}").with(user("sam@example.com").roles("USER"))
        ).andExpect(status().isNotFound)
    }

    @Test
    fun `a visitor cannot delete another visitor's preference`() {
        val stranger = registerUser("alex@example.com")
        val saved = preferences.save(preferenceFor(stranger.userId!!))

        mockMvc.perform(
            delete("/api/user-preferences/${saved.preferenceId}")
                .with(csrf())
                .with(user("sam@example.com").roles("USER"))
        ).andExpect(status().isNotFound)

        assertTrue(preferences.findById(saved.preferenceId!!).isPresent, "a stranger's row must survive untouched")
    }

    @Test
    fun `serves the stored picture back with its content type`() {
        val saved = preferences.save(preferenceFor(owner.userId!!))

        mockMvc.perform(
            get("/api/user-preferences/${saved.preferenceId}/picture").with(user("sam@example.com").roles("USER"))
        )
            .andExpect(status().isOk)
            .andExpect(content().contentType("image/png"))
    }

    @Test
    fun `updating without a picture keeps the one already on file`() {
        val saved = preferences.save(preferenceFor(owner.userId!!))
        val originalPicture = saved.savedPicture

        mockMvc.perform(
            multipart(HttpMethod.PUT, "/api/user-preferences/${saved.preferenceId}")
                .param("style", "Industrial")
                .with(csrf())
                .with(user("sam@example.com").roles("USER"))
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.style").value("Industrial"))

        val updated = preferences.findByPreferenceIdAndUserId(saved.preferenceId!!, owner.userId!!)
        assertEquals("Industrial", updated?.style)
        assertTrue(originalPicture.contentEquals(updated?.savedPicture), "the picture must be unchanged")
    }

    @Test
    fun `deletes a preference`() {
        val saved = preferences.save(preferenceFor(owner.userId!!))

        mockMvc.perform(
            delete("/api/user-preferences/${saved.preferenceId}")
                .with(csrf())
                .with(user("sam@example.com").roles("USER"))
        ).andExpect(status().isNoContent)

        assertTrue(preferences.findById(saved.preferenceId!!).isEmpty)
    }

    @Test
    fun `an anonymous caller is turned away`() {
        mockMvc.perform(get("/api/user-preferences")).andExpect(status().is3xxRedirection)
    }

    private fun preferenceFor(userId: UUID) = UserImages(
        userId = userId,
        savedPicture = square(1024),
        pictureContentType = "image/png",
        style = "Scandinavian",
    )
}

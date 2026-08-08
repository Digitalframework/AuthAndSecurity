package com.inigo.AuthAndSecurity.registration

import com.inigo.AuthAndSecurity.entity.Permission
import com.inigo.AuthAndSecurity.onetimetoken.MutableClock
import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenTestConfig
import com.inigo.AuthAndSecurity.onetimetoken.RecordingEmailService
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import com.inigo.AuthAndSecurity.repositories.IssuedTokenRepository
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.context.annotation.Import
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.LocalDate
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest(
    properties = [
        "spring.security.oauth2.client.registration.google.client-id=test-client-id",
        "spring.security.oauth2.client.registration.google.client-secret=test-client-secret",
        "app.ott.resend-cooldown=0s",
        "app.ott.base-url=https://app.example.test",
    ]
)
@AutoConfigureMockMvc
@Import(OneTimeTokenTestConfig::class)
class RegistrationFlowTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var email: RecordingEmailService

    @Autowired
    private lateinit var clock: MutableClock

    @Autowired
    private lateinit var tokens: IssuedTokenRepository

    @Autowired
    private lateinit var users: AppUserRepository

    @BeforeEach
    fun setUp() {
        clock.reset()
        email.clear()
        tokens.deleteAll()
        users.deleteAll()
    }

    private fun submit(
        email: String = "sam@example.com",
        firstname: String = "Sam",
        surname: String = "Example",
        // MutableClock.START is 2026-01-01, so this is a comfortably adult 31.
        dateOfBirth: String = "1995-01-01",
    ) = mockMvc.perform(
        post("/register")
            .param("email", email)
            .param("firstname", firstname)
            .param("surname", surname)
            .param("dateOfBirth", dateOfBirth)
            .with(csrf())
    )

    @Test
    fun `registering writes an unverified row and emails a confirmation link`() {
        submit().andExpect(redirectedUrl("/ott/sent"))

        val user = users.findByEmail("sam@example.com")
        assertNotNull(user)
        assertEquals("Sam", user.firstname)
        assertEquals("Example", user.surname)
        assertEquals(LocalDate.of(1995, 1, 1), user.dateOfBirth)
        assertNull(user.verifiedAt, "the row must stay unverified until the link is redeemed")
        assertEquals(setOf(Permission.USER), user.permissions)

        val sent = email.lastFor("sam@example.com")
        assertTrue(sent.verification, "registration must send the verification wording, not the sign-in one")
    }

    @Test
    fun `an unverified account cannot sign in without redeeming the link`() {
        submit()

        mockMvc.perform(post("/ott/generate").param("username", "sam@example.com").with(csrf()))
            .andExpect(redirectedUrl("/ott/sent"))
        // Silently refused: nothing new was emailed for the still-unverified address.
        assertEquals(1, email.count, "no sign-in link may be issued before registration is confirmed")
    }

    @Test
    fun `redeeming the registration link confirms the account and signs the visitor in`() {
        submit()
        val token = email.lastFor("sam@example.com").token

        mockMvc.perform(post("/login/ott").param("token", token).with(csrf()))
            .andExpect(status().is3xxRedirection)
            .andExpect(authenticated().withUsername("sam@example.com"))

        val user = users.findByEmail("sam@example.com")
        assertNotNull(user)
        assertNotNull(user.verifiedAt, "redeeming the token must confirm the registration")
    }

    @Test
    fun `once confirmed, an ordinary sign-in link works`() {
        submit()
        val registerToken = email.lastFor("sam@example.com").token
        mockMvc.perform(post("/login/ott").param("token", registerToken).with(csrf()))

        email.clear()
        mockMvc.perform(post("/ott/generate").param("username", "sam@example.com").with(csrf()))
            .andExpect(redirectedUrl("/ott/sent"))
        val signInToken = email.lastFor("sam@example.com").token
        assertTrue(!email.lastFor("sam@example.com").verification, "a later sign-in must use the sign-in wording")

        mockMvc.perform(post("/login/ott").param("token", signInToken).with(csrf()))
            .andExpect(authenticated().withUsername("sam@example.com"))
    }

    @Test
    fun `registering again for an already-confirmed address changes nothing but still emails a link`() {
        submit(firstname = "Sam")
        val firstToken = email.lastFor("sam@example.com").token
        mockMvc.perform(post("/login/ott").param("token", firstToken).with(csrf()))

        email.clear()
        submit(firstname = "Someone-Else").andExpect(redirectedUrl("/ott/sent"))

        val user = users.findByEmail("sam@example.com")
        assertEquals("Sam", user?.firstname, "a confirmed row must not be rewritten by a later registration attempt")

        val sent = email.lastFor("sam@example.com")
        assertTrue(!sent.verification, "the address is already registered, so this is just a way back in")
    }

    @Test
    fun `a second unverified registration overwrites the pending details`() {
        submit(firstname = "Sam")
        email.clear()

        submit(firstname = "Sammy").andExpect(redirectedUrl("/ott/sent"))

        val user = users.findByEmail("sam@example.com")
        assertEquals("Sammy", user?.firstname)
        assertNull(user?.verifiedAt)
    }

    @Test
    fun `someone under the minimum age is turned away without writing anything`() {
        // MutableClock.START is 2026-01-01, so this is a 15-year-old.
        submit(dateOfBirth = "2010-06-01")
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("at least 16")))

        assertTrue(users.findAll().isEmpty())
        assertEquals(0, email.count)
    }

    @Test
    fun `a malformed submission is rejected without writing anything`() {
        submit(email = "not-an-address")
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("does not look like")))

        assertTrue(users.findAll().isEmpty())
        assertEquals(0, email.count)
    }

    @Test
    fun `the registration page is reachable while signed out`() {
        mockMvc.perform(get("/register")).andExpect(status().isOk)
    }
}

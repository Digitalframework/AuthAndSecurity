package com.inigo.AuthAndSecurity.onetimetoken

import com.inigo.AuthAndSecurity.entity.AppUser
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import com.inigo.AuthAndSecurity.repositories.IssuedTokenRepository
import com.inigo.AuthAndSecurity.services.PersistentOneTimeTokenService
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Import
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest
import org.hamcrest.Matchers.containsString
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Duration
import java.time.LocalDate
import kotlin.test.assertEquals
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
class OneTimeTokenLoginFlowTest {

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
        // Only a confirmed account can be sent a sign-in link at all, so every test
        // below that asks for one starts from an already-registered visitor.
        register("sam@example.com")
    }

    private fun register(address: String) {
        users.save(
            AppUser(
                email = address,
                firstname = "Sam",
                surname = "Example",
                dateOfBirth = LocalDate.of(1995, 1, 1),
                createdAt = clock.instant(),
                verifiedAt = clock.instant(),
            )
        )
    }

    private fun requestLink(address: String) =
        mockMvc.perform(post("/ott/generate").param("username", address).with(csrf()))

    @Test
    fun `the whole flow signs a visitor in`() {
        requestLink("sam@example.com")
            .andExpect(status().is3xxRedirection)
            .andExpect(redirectedUrl("/ott/sent"))

        val sent = email.lastFor("sam@example.com")
        assertEquals("https://app.example.test/login/ott?token=${sent.token}", sent.link)

        // The link lands on a page rather than signing anyone in, so a scanner
        // that follows it cannot spend the token.
        mockMvc.perform(get("/login/ott").param("token", sent.token))
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString(sent.token)))
            .andExpect(unauthenticated())

        mockMvc.perform(post("/login/ott").param("token", sent.token).with(csrf()))
            .andExpect(status().is3xxRedirection)
            .andExpect(authenticated().withUsername("sam@example.com"))
    }

    @Test
    fun `a token works only once`() {
        requestLink("sam@example.com")
        val token = email.lastFor("sam@example.com").token

        mockMvc.perform(post("/login/ott").param("token", token).with(csrf()))
            .andExpect(authenticated())

        mockMvc.perform(post("/login/ott").param("token", token).with(csrf()))
            .andExpect(redirectedUrl("/login?error=invalid"))
            .andExpect(unauthenticated())
    }

    @Test
    fun `a made-up token is refused`() {
        mockMvc.perform(post("/login/ott").param("token", "not-a-real-token").with(csrf()))
            .andExpect(redirectedUrl("/login?error=invalid"))
            .andExpect(unauthenticated())
    }

    @Test
    fun `an expired token is refused`() {
        requestLink("sam@example.com")
        val token = email.lastFor("sam@example.com").token

        clock.advance(Duration.ofMinutes(11))

        mockMvc.perform(post("/login/ott").param("token", token).with(csrf()))
            .andExpect(redirectedUrl("/login?error=invalid"))
            .andExpect(unauthenticated())
    }

    @Test
    fun `the generate endpoint requires a CSRF token`() {
        mockMvc.perform(post("/ott/generate").param("username", "sam@example.com"))
            .andExpect(status().isForbidden)

        assertEquals(0, email.count, "nothing should have been emailed")
    }

    @Test
    fun `a malformed address never reaches the token generator`() {
        mockMvc.perform(post("/ott/generate").param("username", "not-an-address").with(csrf()))
            .andExpect(redirectedUrl("/login?error=email"))

        assertEquals(0, email.count)
        assertTrue(tokens.findAll().isEmpty(), "no token should have been stored")
    }

    @Test
    fun `pages of the sign-in flow are reachable while signed out`() {
        mockMvc.perform(get("/login")).andExpect(status().isOk)
        mockMvc.perform(get("/ott/sent")).andExpect(status().isOk)
        mockMvc.perform(get("/login/ott")).andExpect(status().isOk)
        mockMvc.perform(get("/css/app.css")).andExpect(status().isOk)
    }

    /**
     * A status check alone will not do here. Spring Security's
     * `DefaultLoginPageGeneratingFilter` answers /login with a generated form of its
     * own and returns 200 for it, so it shadowed this application's page while every
     * assertion still passed. What distinguishes the two is the Google link, which
     * the generated page has no way to offer once oauth2Login names a custom login
     * page.
     */
    @Test
    fun `the login page is this application's own, offering both ways in`() {
        val page = mockMvc.perform(get("/login"))
            .andExpect(status().isOk)
            .andReturn().response.contentAsString

        assertTrue("/oauth2/authorization/google" in page, "the Google button must be on the page")
        assertTrue("/ott/generate" in page, "the form must post to the token generator")
        assertTrue(
            "Request a One-Time Token" !in page,
            "this is Spring Security's generated page, not the application's",
        )
    }

    @Test
    fun `everything else demands a session`() {
        mockMvc.perform(get("/"))
            .andExpect(status().is3xxRedirection)
            .andExpect(redirectedUrl("/login"))

        mockMvc.perform(get("/api/user"))
            .andExpect(status().is3xxRedirection)
    }

    /**
     * The other three templates are rendered by the tests above, but the home page
     * only ever appeared here as the redirect a signed-out visitor gets — so a
     * template that could not be parsed at all still passed. It is rendered for
     * both kinds of principal because they take different branches through it.
     */
    @Test
    fun `the home page renders for a visitor who signed in with a link`() {
        mockMvc.perform(get("/").with(user("sam@example.com").roles("USER")))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("sam@example.com")))
            .andExpect(content().string(containsString("Signed in with an emailed link")))
    }

    @Test
    fun `the home page renders for a visitor who signed in with Google`() {
        mockMvc.perform(
            get("/").with(
                oidcLogin().idToken { it.claim("email", "sam@example.com").claim("name", "Sam") }
            )
        )
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("Sam")))
            .andExpect(content().string(containsString("Signed in with Google")))
    }

    @Test
    fun `the confirmation page gives nothing away about the address`() {
        val forAKnownAddress = mockMvc.perform(get("/ott/sent")).andReturn().response.contentAsString

        requestLink("sam@example.com")
        val afterASend = mockMvc.perform(get("/ott/sent")).andReturn().response.contentAsString

        assertEquals(forAKnownAddress, afterASend)
        assertTrue("sam@example.com" !in afterASend, "the page must not echo the address back")
    }
}

@SpringBootTest(
    properties = [
        "spring.security.oauth2.client.registration.google.client-id=test-client-id",
        "spring.security.oauth2.client.registration.google.client-secret=test-client-secret",
        "app.ott.resend-cooldown=60s",
        "app.ott.max-per-window=2",
        "app.ott.allowed-domains[0]=example.com",
    ]
)
@AutoConfigureMockMvc
@Import(OneTimeTokenTestConfig::class)
class OneTimeTokenThrottlingTest {

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

    /**
     * The real bean, not a hand-built one: `generate` is `@Transactional`, and a
     * plain constructor call gets no proxy and so no transaction.
     */
    @Autowired
    private lateinit var tokenService: PersistentOneTimeTokenService

    @BeforeEach
    fun setUp() {
        clock.reset()
        email.clear()
        tokens.deleteAll()
        users.deleteAll()
        // Only a confirmed account may be sent a sign-in link, so every request
        // below is against an address that has already gone through registration.
        users.save(
            AppUser(
                email = "sam@example.com",
                firstname = "Sam",
                surname = "Example",
                dateOfBirth = LocalDate.of(1995, 1, 1),
                createdAt = clock.instant(),
                verifiedAt = clock.instant(),
            )
        )
    }

    private fun requestLink(address: String) =
        mockMvc.perform(post("/ott/generate").param("username", address).with(csrf()))

    @Test
    fun `a resend inside the cooldown is turned away with a Retry-After`() {
        requestLink("sam@example.com").andExpect(redirectedUrl("/ott/sent"))
        clock.advance(Duration.ofSeconds(10))

        requestLink("sam@example.com")
            .andExpect(redirectedUrl("/login?error=throttled&retryAfter=50"))
            .andExpect(header().string("Retry-After", "50"))

        assertEquals(1, email.count, "the second request must not have emailed anything")
    }

    @Test
    fun `running out of window quota is turned away`() {
        requestLink("sam@example.com")
        clock.advance(Duration.ofSeconds(61))
        requestLink("sam@example.com")
        clock.advance(Duration.ofSeconds(61))

        requestLink("sam@example.com").andExpect(redirectedUrl("/login?error=quota"))

        assertEquals(2, email.count)
    }

    @Test
    fun `an address off the allowlist is refused indistinguishably from a success`() {
        val refused = requestLink("intruder@elsewhere.test")
            .andExpect(redirectedUrl("/ott/sent"))
            .andReturn().response

        assertEquals(0, email.count, "nothing may be emailed to an address off the allowlist")
        assertTrue(tokens.findAll().isEmpty(), "no token may be stored for an address off the allowlist")

        // Byte-for-byte the same as the accepted path, which is the whole point.
        clock.advance(Duration.ofSeconds(61))
        val accepted = requestLink("sam@example.com").andReturn().response
        assertEquals(accepted.status, refused.status)
        assertEquals(accepted.getHeader("Location"), refused.getHeader("Location"))
    }

    @Test
    fun `a link already in an inbox stops working once the address leaves the allowlist`() {
        // The allowlist is checked again at redemption, minutes after generation.
        // Here the address was never on it, and the token is minted straight from
        // the service — bypassing the generate endpoint's checks — to stand in for
        // one issued before the list changed.
        val issued = tokenService.generate(
            GenerateOneTimeTokenRequest("intruder@elsewhere.test", Duration.ofMinutes(10))
        )

        mockMvc.perform(post("/login/ott").param("token", issued.tokenValue).with(csrf()))
            .andExpect(redirectedUrl("/login?error=invalid"))
            .andExpect(unauthenticated())
    }
}
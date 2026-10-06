package com.inigo.AuthAndSecurity.tokens

import com.inigo.AuthAndSecurity.controller.UserController
import com.inigo.AuthAndSecurity.entity.AppUser
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import com.inigo.AuthAndSecurity.services.AccessTokenService
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant
import java.time.LocalDate
import kotlin.test.assertEquals

/**
 * The two endpoints generation-backend calls, driven the way it drives them: with a
 * real token from `/api/token` in an `Authorization` header.
 *
 * Deliberately not with the `jwt()` post-processor, which would install an
 * authentication and skip the decoder entirely — the parts most worth testing here
 * are exactly the ones it would bypass, since a signature or audience check that
 * silently passes everything looks identical to one that works.
 */
@SpringBootTest(
    properties = [
        "spring.security.oauth2.client.registration.google.client-id=test-client-id",
        "spring.security.oauth2.client.registration.google.client-secret=test-client-secret",
    ]
)
@AutoConfigureMockMvc
class TokenBalanceEndpointsTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var users: AppUserRepository

    @Autowired
    private lateinit var tokens: AccessTokenService

    private lateinit var owner: AppUser

    @BeforeEach
    fun setUp() {
        users.deleteAll()
        owner = registerUser("sam@example.com", balance = 25)
    }

    private fun registerUser(email: String, balance: Int): AppUser = users.save(
        AppUser(
            email = email,
            firstname = "Sam",
            surname = "Example",
            dateOfBirth = LocalDate.of(1995, 1, 1),
            tokenBalance = balance,
            createdAt = Instant.now(),
            verifiedAt = Instant.now(),
        )
    )

    private fun bearerFor(user: AppUser) = "Bearer ${tokens.issueFor(user).accessToken}"

    private fun balanceOf(user: AppUser) = users.findById(requireNotNull(user.userId)).orElseThrow().tokenBalance

    @Test
    fun `reports the balance of whoever the token names`() {
        mockMvc.perform(
            get(UserController.BALANCE_URL).header(HttpHeaders.AUTHORIZATION, bearerFor(owner))
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.tokenBalance").value(25))
    }

    @Test
    fun `spending debits the balance and reports what is left`() {
        mockMvc.perform(
            post(UserController.SPEND_URL)
                .header(HttpHeaders.AUTHORIZATION, bearerFor(owner))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"amount":10}""")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.tokenBalance").value(15))

        assertEquals(15, balanceOf(owner), "the debit must reach the database, not just the response")
    }

    @Test
    fun `refuses to spend more than the balance covers, and takes nothing`() {
        mockMvc.perform(
            post(UserController.SPEND_URL)
                .header(HttpHeaders.AUTHORIZATION, bearerFor(owner))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"amount":26}""")
        ).andExpect(status().isPaymentRequired)

        assertEquals(25, balanceOf(owner), "a refused spend must leave the balance untouched")
    }

    /** The boundary either side of which the conditional UPDATE has to decide differently. */
    @Test
    fun `spending the whole balance is allowed, one more is not`() {
        mockMvc.perform(
            post(UserController.SPEND_URL)
                .header(HttpHeaders.AUTHORIZATION, bearerFor(owner))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"amount":25}""")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.tokenBalance").value(0))

        mockMvc.perform(
            post(UserController.SPEND_URL)
                .header(HttpHeaders.AUTHORIZATION, bearerFor(owner))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"amount":1}""")
        ).andExpect(status().isPaymentRequired)
    }

    /**
     * The one that would turn a spend into a top-up. Caught by validation before the
     * query runs, so the `where` clause never gets the chance to find a negative
     * amount affordable.
     */
    @Test
    fun `refuses a negative or zero amount`() {
        for (amount in listOf(0, -5)) {
            mockMvc.perform(
                post(UserController.SPEND_URL)
                    .header(HttpHeaders.AUTHORIZATION, bearerFor(owner))
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""{"amount":$amount}""")
            ).andExpect(status().isBadRequest)
        }

        assertEquals(25, balanceOf(owner))
    }

    /**
     * Two accounts, and a token for one used to ask about both. The balance reported
     * has to be the token's owner's, because the request body and query string carry
     * nothing that could redirect it.
     */
    @Test
    fun `a token can only reach its own balance`() {
        val stranger = registerUser("alex@example.com", balance = 500)

        mockMvc.perform(
            get(UserController.BALANCE_URL).header(HttpHeaders.AUTHORIZATION, bearerFor(owner))
        ).andExpect(jsonPath("$.tokenBalance").value(25))

        mockMvc.perform(
            post(UserController.SPEND_URL)
                .header(HttpHeaders.AUTHORIZATION, bearerFor(owner))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"amount":10}""")
        ).andExpect(status().isOk)

        assertEquals(500, balanceOf(stranger), "spending must not touch anyone else's balance")
    }

    @Test
    fun `a caller with no token gets 401 rather than a redirect to the login page`() {
        mockMvc.perform(get(UserController.BALANCE_URL)).andExpect(status().isUnauthorized)
    }

    @Test
    fun `a token that was not signed by this application is refused`() {
        mockMvc.perform(
            get(UserController.BALANCE_URL).header(HttpHeaders.AUTHORIZATION, "Bearer not.a.token")
        ).andExpect(status().isUnauthorized)
    }

    /** No cookie is read on this chain, so a POST without a CSRF token has to work. */
    @Test
    fun `spending needs no CSRF token`() {
        mockMvc.perform(
            post(UserController.SPEND_URL)
                .header(HttpHeaders.AUTHORIZATION, bearerFor(owner))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"amount":1}""")
        ).andExpect(status().isOk)
    }
}

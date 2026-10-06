package com.inigo.AuthAndSecurity.payment

import com.inigo.AuthAndSecurity.entity.AppUser
import com.inigo.AuthAndSecurity.entity.TokenPurchase
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import com.inigo.AuthAndSecurity.repositories.TokenPurchaseRepository
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.context.annotation.Primary
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The PayPal round trip, with PayPal itself stood in for.
 *
 * The point of these is the return leg. A visitor coming back arrives by a GET
 * they can repeat, edit and share, so what matters is not that the happy path
 * works but that everything else refuses: a replayed URL, someone else's order,
 * an amount that does not match, an order PayPal never approved.
 */
@SpringBootTest(
    properties = [
        "spring.security.oauth2.client.registration.google.client-id=test-client-id",
        "spring.security.oauth2.client.registration.google.client-secret=test-client-secret",
        "app.paypal.client-id=test-paypal-id",
        "app.paypal.client-secret=test-paypal-secret",
    ]
)
@AutoConfigureMockMvc
@Import(PaypalFlowTest.FakePaypalConfig::class)
class PaypalFlowTest {

    @Autowired private lateinit var mockMvc: MockMvc
    @Autowired private lateinit var users: AppUserRepository
    @Autowired private lateinit var purchases: TokenPurchaseRepository
    @Autowired private lateinit var payPal: FakePaypalClient

    private lateinit var owner: AppUser

    @BeforeEach
    fun setUp() {
        purchases.deleteAll()
        users.deleteAll()
        payPal.reset()
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

    private fun balanceOf(user: AppUser): Int = users.findById(user.userId!!).orElseThrow().tokenBalance

    /** A purchase already opened and waiting for the visitor to come back. */
    private fun openPurchase(user: AppUser, pack: TokenPack = TokenPack.SMALL): TokenPurchase = purchases.save(
        TokenPurchase(
            userId = user.userId!!,
            pack = pack,
            tokens = pack.tokens,
            amount = pack.price,
            currency = "EUR",
            paypalOrderId = ORDER_ID,
            createdAt = Instant.now(),
        )
    )

    private fun approved(amount: BigDecimal = TokenPack.SMALL.price, currency: String = "EUR") =
        PaypalOrder(id = ORDER_ID, status = "APPROVED", amount = amount, currency = currency)

    private fun buy(pack: String = "SMALL", vararg extras: Pair<String, String>) =
        post("/paypal/create")
            .param("pack", pack)
            .apply { extras.forEach { (k, v) -> param(k, v) } }
            .with(csrf())
            .with(user("sam@example.com").roles("USER"))

    private fun comeBack(orderId: String = ORDER_ID, signedInAs: String = "sam@example.com") =
        get("/paypal/success").param("token", orderId).with(user(signedInAs).roles("USER"))

    /** What was actually sent to PayPal as the amount. */
    private fun amountSentToPayPal(): String {
        val units = payPal.payloads.single()["purchase_units"] as List<*>
        val amount = (units.single() as Map<*, *>)["amount"] as Map<*, *>
        return amount["value"] as String
    }

    @Test
    fun `starting a purchase forwards to PayPal and records the order`() {
        mockMvc.perform(buy())
            .andExpect(status().is3xxRedirection)
            .andExpect(redirectedUrl(APPROVE_URL))

        val saved = purchases.findAll().single()
        assertEquals(owner.userId, saved.userId)
        assertEquals(ORDER_ID, saved.paypalOrderId)
        assertNull(saved.creditedAt, "nothing is credited before the visitor comes back")
        assertEquals(0, balanceOf(owner))
    }

    @Test
    fun `the price comes from the pack, not from the request`() {
        mockMvc.perform(buy("SMALL", "amount" to "0.01", "tokens" to "999999", "price" to "0.01"))
            .andExpect(status().is3xxRedirection)

        val saved = purchases.findAll().single()
        assertEquals(TokenPack.SMALL.tokens, saved.tokens)
        assertEquals(0, TokenPack.SMALL.price.compareTo(saved.amount))
        assertEquals(TokenPack.SMALL.amountValue(), amountSentToPayPal())
    }

    @Test
    fun `an unknown pack is refused`() {
        mockMvc.perform(buy("ENORMOUS")).andExpect(status().isBadRequest)
        assertTrue(purchases.findAll().isEmpty())
    }

    @Test
    fun `starting a purchase without a CSRF token is refused`() {
        mockMvc.perform(
            post("/paypal/create").param("pack", "SMALL").with(user("sam@example.com").roles("USER"))
        ).andExpect(status().isForbidden)

        assertTrue(purchases.findAll().isEmpty())
    }

    @Test
    fun `an approved order credits the tokens`() {
        openPurchase(owner)
        payPal.orders[ORDER_ID] = approved()

        mockMvc.perform(comeBack()).andExpect(redirectedUrl("/?purchase=ok"))

        assertEquals(TokenPack.SMALL.tokens, balanceOf(owner))
        assertNotNull(purchases.findAll().single().creditedAt)
    }

    @Test
    fun `replaying the return URL credits only once`() {
        openPurchase(owner)
        payPal.orders[ORDER_ID] = approved()

        mockMvc.perform(comeBack()).andExpect(redirectedUrl("/?purchase=ok"))
        mockMvc.perform(comeBack()).andExpect(redirectedUrl("/?purchase=already"))
        mockMvc.perform(comeBack()).andExpect(redirectedUrl("/?purchase=already"))

        assertEquals(TokenPack.SMALL.tokens, balanceOf(owner), "the return URL must not be a token faucet")
    }

    @Test
    fun `an order PayPal reports a different amount for is refused`() {
        openPurchase(owner)
        payPal.orders[ORDER_ID] = approved(amount = BigDecimal("0.01"))

        mockMvc.perform(comeBack()).andExpect(redirectedUrl("/?purchase=unapproved"))

        assertEquals(0, balanceOf(owner))
        assertNull(purchases.findAll().single().creditedAt)
    }

    @Test
    fun `an order in a different currency is refused`() {
        openPurchase(owner)
        payPal.orders[ORDER_ID] = approved(currency = "VND")

        mockMvc.perform(comeBack()).andExpect(redirectedUrl("/?purchase=unapproved"))
        assertEquals(0, balanceOf(owner))
    }

    @Test
    fun `an order the visitor never approved is refused`() {
        openPurchase(owner)
        payPal.orders[ORDER_ID] = PaypalOrder(ORDER_ID, "PAYER_ACTION_REQUIRED", null, TokenPack.SMALL.price, "EUR")

        mockMvc.perform(comeBack()).andExpect(redirectedUrl("/?purchase=unapproved"))

        assertEquals(0, balanceOf(owner))
        assertNull(purchases.findAll().single().creditedAt)
    }

    @Test
    fun `a visitor cannot complete another visitor's purchase`() {
        val stranger = registerUser("alex@example.com")
        openPurchase(stranger)
        payPal.orders[ORDER_ID] = approved()

        mockMvc.perform(comeBack()).andExpect(status().isNotFound)

        assertEquals(0, balanceOf(owner), "an order belonging to someone else must credit nobody")
        assertEquals(0, balanceOf(stranger))
        assertNull(purchases.findAll().single().creditedAt)
    }

    @Test
    fun `an order id that was never opened is refused`() {
        payPal.orders["MADE-UP"] = approved()

        mockMvc.perform(comeBack(orderId = "MADE-UP")).andExpect(status().isNotFound)
        assertEquals(0, balanceOf(owner))
    }

    @Test
    fun `cancelling adds nothing`() {
        openPurchase(owner)

        mockMvc.perform(get("/paypal/cancel").with(user("sam@example.com").roles("USER")))
            .andExpect(redirectedUrl("/?purchase=cancelled"))

        assertEquals(0, balanceOf(owner))
        assertNull(purchases.findAll().single().creditedAt)
    }

    @Test
    fun `PayPal being unreachable adds nothing`() {
        openPurchase(owner)
        // No order registered with the fake, so getOrder throws.

        mockMvc.perform(comeBack()).andExpect(redirectedUrl("/?purchase=error"))

        assertEquals(0, balanceOf(owner))
        assertNull(purchases.findAll().single().creditedAt)
    }

    @Test
    fun `an anonymous caller is turned away`() {
        mockMvc.perform(get("/paypal/success").param("token", ORDER_ID))
            .andExpect(status().is3xxRedirection)
        mockMvc.perform(post("/paypal/create").param("pack", "SMALL").with(csrf()))
            .andExpect(status().is3xxRedirection)

        assertTrue(purchases.findAll().isEmpty())
    }

    /**
     * A hand-written double rather than a mock: the flow needs `createOrder` and
     * `getOrder` to agree about the same order across two requests, and that state
     * reads better as a small class than as a pile of stubbings.
     */
    class FakePaypalClient : PaypalClient(PaypalProperties(), Clock.systemUTC()) {

        /** What the next [createOrder] hands back. */
        var created: PaypalOrder = PaypalOrder(ORDER_ID, "PAYER_ACTION_REQUIRED", APPROVE_URL)

        /** Orders [getOrder] knows about. An id that is not here stands for PayPal failing. */
        val orders: MutableMap<String, PaypalOrder> = mutableMapOf()

        /** Every payload sent, so a test can check what actually went to PayPal. */
        val payloads: MutableList<Map<String, Any>> = mutableListOf()

        fun reset() {
            created = PaypalOrder(ORDER_ID, "PAYER_ACTION_REQUIRED", APPROVE_URL)
            orders.clear()
            payloads.clear()
        }

        override fun createOrder(order: Map<String, Any>, requestId: String): PaypalOrder {
            payloads += order
            return created
        }

        override fun getOrder(orderId: String): PaypalOrder =
            orders[orderId] ?: throw PaypalException("Fake PayPal has no order $orderId")
    }

    @TestConfiguration
    class FakePaypalConfig {
        /** `@Primary` so it wins over the real [PaypalClient] component. */
        @Bean
        @Primary
        fun fakePaypalClient(): FakePaypalClient = FakePaypalClient()
    }

    companion object {
        const val ORDER_ID = "TEST-ORDER-1"
        const val APPROVE_URL = "https://www.sandbox.paypal.example/checkoutnow?token=TEST-ORDER-1"
    }
}

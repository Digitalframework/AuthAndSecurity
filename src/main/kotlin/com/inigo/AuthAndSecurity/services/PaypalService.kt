package com.inigo.AuthAndSecurity.services

import com.inigo.AuthAndSecurity.entity.TokenPurchase
import com.inigo.AuthAndSecurity.payment.PaymentFactory
import com.inigo.AuthAndSecurity.payment.PaypalClient
import com.inigo.AuthAndSecurity.payment.PaypalException
import com.inigo.AuthAndSecurity.payment.PaypalProperties
import com.inigo.AuthAndSecurity.payment.TokenPack
import com.inigo.AuthAndSecurity.repositories.AppUserRepository
import com.inigo.AuthAndSecurity.repositories.TokenPurchaseRepository
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.server.ResponseStatusException
import java.time.Clock
import java.util.UUID

enum class PaymentResult { CREDITED, ALREADY_CREDITED, NOT_APPROVED }

/**
 * Buying tokens with PayPal, as a demo: the visitor is sent to PayPal, logs in and
 * approves, and comes back to find tokens added. Nothing is ever captured, so no
 * money moves.
 *
 * The whole security question this raises is what to believe on the way back. The
 * answer is: nothing that arrives in the return request. It is a plain GET
 * performed by the visitor's own browser, so its parameters and the number of
 * times it happens are theirs to choose. It is allowed to say *which* order to go
 * and look at, and nothing else. Four things must hold before a token is handed
 * over:
 *
 *  - the order is one this app opened, for the session asking — scoped in the
 *    query, so someone else's order id looks exactly like a made-up one;
 *  - PayPal itself, asked directly, says it was approved;
 *  - the amount PayPal reports matches what was recorded when it was opened;
 *  - it has not already been paid out.
 */
@Service
class PaypalService(
    private val purchases: TokenPurchaseRepository,
    private val users: AppUserRepository,
    private val resolver: AuthenticatedUserResolver,
    private val paypal: PaypalClient,
    private val factory: PaymentFactory,
    private val properties: PaypalProperties,
    private val clock: Clock,
) {

    private val log = LoggerFactory.getLogger(javaClass)

    /** Opens a purchase and returns the PayPal URL to send the visitor to. */
    fun createPayment(authentication: Authentication?, pack: TokenPack, request: HttpServletRequest): String {
        val userId = ownerId(authentication)
        val reference = UUID.randomUUID().toString()
        val base = appBaseUrl(request)

        val order = paypal.createOrder(
            factory.createOrder(reference, pack, "$base$SUCCESS_PATH", "$base$CANCEL_PATH"),
            requestId = reference,
        )
        val approveUrl = order.approveUrl
            ?: throw PaypalException("PayPal created order ${order.id} without an approval link.")

        purchases.save(
            TokenPurchase(
                userId = userId,
                pack = pack,
                tokens = pack.tokens,
                amount = pack.price,
                currency = properties.currency,
                paypalOrderId = order.id,
                createdAt = clock.instant(),
            )
        )
        return approveUrl
    }

    /**
     * Handles the visitor coming back approved.
     *
     * @param orderId PayPal appends this as `token`, which has nothing to do with
     *   either the sign-in tokens or the ones being bought. Used purely as a lookup
     *   key, and trusted for nothing else.
     */
    @Transactional
    fun executePayment(authentication: Authentication?, orderId: String): PaymentResult {
        val userId = ownerId(authentication)
        val purchase = purchases.findByPaypalOrderIdAndUserId(orderId, userId)
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "No such purchase.")

        val order = paypal.getOrder(orderId)
        // APPROVED is where an uncaptured order stops. COMPLETED is accepted too so
        // that turning capture on later does not start rejecting good purchases.
        val approved = (order.status == "APPROVED" || order.status == "COMPLETED") &&
            // Fails closed on a missing amount. compareTo, not equals: "4.99" and
            // 4.99 are equal numbers and unequal BigDecimals.
            order.amount?.compareTo(purchase.amount) == 0 &&
            order.currency == purchase.currency

        if (!approved) {
            log.warn(
                "Refusing purchase {}: PayPal reports {} {} {}, expected APPROVED {} {}",
                purchase.purchaseId, order.status, order.amount, order.currency,
                purchase.amount, purchase.currency,
            )
            return PaymentResult.NOT_APPROVED
        }

        // Nothing below runs unless this request was the one that closed the latch,
        // so a replayed return URL credits nobody twice.
        if (purchases.claim(requireNotNull(purchase.purchaseId), clock.instant()) == 0) {
            return PaymentResult.ALREADY_CREDITED
        }

        val user = users.findById(userId).orElseThrow()
        user.tokenBalance += purchase.tokens
        users.save(user)

        log.info("Credited {} tokens to user {} for order {}", purchase.tokens, userId, orderId)
        return PaymentResult.CREDITED
    }

    /** Only a session with a row in `app_user` has a balance to credit. Same rule as [UserImagesService]. */
    private fun ownerId(authentication: Authentication?): UUID =
        resolver.resolve(authentication)?.userId
            ?: throw ResponseStatusException(HttpStatus.FORBIDDEN, "No registered account behind this session.")

    /** Prefers the configured base URL, for the reason [com.inigo.AuthAndSecurity.onetimetoken.SignInLinkBuilder] gives. */
    private fun appBaseUrl(request: HttpServletRequest): String {
        properties.appBaseUrl?.let { return it.trimEnd('/') }
        val port = request.serverPort
        val defaultPort = (request.scheme == "http" && port == 80) || (request.scheme == "https" && port == 443)
        val authority = if (defaultPort) request.serverName else "${request.serverName}:$port"
        return "${request.scheme}://$authority${request.contextPath}"
    }

    companion object {
        const val SUCCESS_PATH = "/paypal/success"
        const val CANCEL_PATH = "/paypal/cancel"
    }
}

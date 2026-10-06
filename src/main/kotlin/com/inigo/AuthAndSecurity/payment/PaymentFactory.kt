package com.inigo.AuthAndSecurity.payment

import org.springframework.stereotype.Component

/**
 * Assembles the pieces of a PayPal Orders v2 request, so [PaypalClient] only has
 * to send them and [com.inigo.AuthAndSecurity.services.PaypalService] only has to
 * decide what a purchase means.
 *
 * The amount is always read off [TokenPack] here, never passed in, which is what
 * keeps the price out of reach of the request.
 */
@Component
class PaymentFactory(
    private val properties: PaypalProperties,
) {

    fun createAmount(pack: TokenPack): Map<String, Any> = mapOf(
        "currency_code" to properties.currency,
        "value" to pack.amountValue(),
    )

    fun createPurchaseUnit(reference: String, pack: TokenPack): Map<String, Any> = buildMap {
        put("reference_id", reference)
        put("description", "${pack.tokens} tokens")
        put("amount", createAmount(pack))
        properties.payeeEmail?.takeIf { it.isNotBlank() }?.let {
            put("payee", mapOf("email_address" to it))
        }
    }

    fun createRedirectUrls(returnUrl: String, cancelUrl: String): Map<String, Any> = mapOf(
        "brand_name" to properties.brandName,
        // Ask for the sign-in screen rather than the guest card form: logging in to
        // PayPal is the whole point of this demo.
        "landing_page" to "LOGIN",
        "user_action" to "PAY_NOW",
        "shipping_preference" to "NO_SHIPPING",
        "return_url" to returnUrl,
        "cancel_url" to cancelUrl,
    )

    /**
     * `intent` is CAPTURE because that is what the order describes. Capture is
     * never called, so the order stops at APPROVED and no money moves.
     */
    fun createOrder(reference: String, pack: TokenPack, returnUrl: String, cancelUrl: String): Map<String, Any> = mapOf(
        "intent" to "CAPTURE",
        "purchase_units" to listOf(createPurchaseUnit(reference, pack)),
        "payment_source" to mapOf(
            "paypal" to mapOf("experience_context" to createRedirectUrls(returnUrl, cancelUrl))
        ),
    )
}

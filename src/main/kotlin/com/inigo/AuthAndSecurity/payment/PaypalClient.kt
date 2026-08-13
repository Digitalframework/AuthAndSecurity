package com.inigo.AuthAndSecurity.payment

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestClientResponseException
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant

/** Anything that stopped a PayPal call from producing a usable answer. */
class PaypalException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * @property status PayPal's own word for the order. `APPROVED` is where one stops
 *   once the visitor has logged in and clicked through and nothing was captured.
 */
data class PaypalOrder(
    val id: String,
    val status: String,
    val approveUrl: String? = null,
    val amount: BigDecimal? = null,
    val currency: String? = null,
)

/**
 * The two Orders v2 calls this demo makes: open an order, read one back.
 *
 * *Capture* — the call that actually moves money — is deliberately absent. An
 * order therefore stops at APPROVED, which proves the visitor logged in to PayPal
 * and approved, and takes nothing from them.
 */
@Component
class PaypalClient(
    private val properties: PaypalProperties,
    private val clock: Clock,
) {

    private val http = RestClient.builder().baseUrl(properties.apiBaseUrl).build()

    @Volatile
    private var token: String? = null

    @Volatile
    private var tokenExpiresAt: Instant = Instant.EPOCH

    fun createOrder(order: Map<String, Any>, requestId: String): PaypalOrder = call("create order") {
        http.post()
            .uri("/v2/checkout/orders")
            .header("Authorization", "Bearer ${accessToken()}")
            // Makes a retry return the original order rather than opening a second.
            .header("PayPal-Request-Id", requestId)
            .contentType(MediaType.APPLICATION_JSON)
            .body(order)
            .retrieve()
            .body(OrderResponse::class.java)
    }.toOrder()

    /** The only trustworthy account of an order: it arrives over a connection the visitor is not part of. */
    fun getOrder(orderId: String): PaypalOrder = call("read order") {
        http.get()
            .uri("/v2/checkout/orders/{id}", orderId)
            .header("Authorization", "Bearer ${accessToken()}")
            .retrieve()
            .body(OrderResponse::class.java)
    }.toOrder()

    private fun accessToken(): String {
        token?.takeIf { tokenExpiresAt.isAfter(clock.instant()) }?.let { return it }

        // Blank rather than null: `app.paypal.client-id=` with nothing after it is an
        // empty string, and reaching PayPal with it would come back as an opaque 401.
        val id = properties.clientId?.takeIf { it.isNotBlank() }
            ?: throw PaypalException("PayPal is not configured: set app.paypal.client-id.")
        val secret = properties.clientSecret?.takeIf { it.isNotBlank() }
            ?: throw PaypalException("PayPal is not configured: set app.paypal.client-secret.")

        val response = call("fetch access token") {
            http.post()
                .uri("/v1/oauth2/token")
                .headers { it.setBasicAuth(id, secret) }
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(LinkedMultiValueMap<String, String>().apply { add("grant_type", "client_credentials") })
                .retrieve()
                .body(TokenResponse::class.java)
        }

        // A minute early, so a token cannot go stale between this check and PayPal.
        tokenExpiresAt = clock.instant().plusSeconds(response.expiresIn - 60)
        return response.accessToken.also { token = it }
    }

    /** PayPal's error bodies name the offending field; losing them to a bare 500 makes misconfiguration hard to spot. */
    private fun <T : Any> call(what: String, block: () -> T?): T =
        try {
            block() ?: throw PaypalException("PayPal returned an empty body on $what.")
        } catch (e: RestClientResponseException) {
            throw PaypalException("PayPal refused to $what (${e.statusCode}): ${e.responseBodyAsString}", e)
        } catch (e: RestClientException) {
            throw PaypalException("Could not reach PayPal to $what.", e)
        }

    private fun OrderResponse.toOrder(): PaypalOrder {
        val paid = purchaseUnits.firstOrNull()?.amount
        return PaypalOrder(
            id = id,
            status = status,
            // "payer-action" is what an experience context yields; "approve" is the older name.
            approveUrl = links.firstOrNull { it.rel == "payer-action" || it.rel == "approve" }?.href,
            amount = paid?.value?.let { runCatching { BigDecimal(it) }.getOrNull() },
            currency = paid?.currencyCode,
        )
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class TokenResponse(
        @param:JsonProperty("access_token") val accessToken: String,
        @param:JsonProperty("expires_in") val expiresIn: Long,
    )

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class OrderResponse(
        val id: String,
        val status: String,
        val links: List<Link> = emptyList(),
        @param:JsonProperty("purchase_units") val purchaseUnits: List<PurchaseUnit> = emptyList(),
    )

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class Link(val href: String, val rel: String)

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class PurchaseUnit(val amount: Amount? = null)

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class Amount(
        @param:JsonProperty("currency_code") val currencyCode: String? = null,
        val value: String? = null,
    )
}

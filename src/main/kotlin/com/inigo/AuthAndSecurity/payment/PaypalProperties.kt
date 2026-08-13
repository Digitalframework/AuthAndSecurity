package com.inigo.AuthAndSecurity.payment

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * PayPal settings, under `app.paypal.`. Credentials default to null rather than
 * being required at startup: unset, buying tokens is simply off — see [configured].
 */
@ConfigurationProperties(prefix = "app.paypal")
data class PaypalProperties(
    val clientId: String? = null,
    val clientSecret: String? = null,

    /** Sandbox by default. Live is `https://api-m.paypal.com`. */
    val apiBaseUrl: String = "https://api-m.sandbox.paypal.com",

    /**
     * Absolute base URL PayPal returns the visitor to. Unset, it is built from the
     * request — right locally, wrong behind a proxy that sends no forwarded headers.
     */
    val appBaseUrl: String? = null,

    val currency: String = "EUR",

    /**
     * Receiving address. Normally leave unset — an order is already payable to the
     * account owning the client id; naming a different one needs a partner setup.
     */
    val payeeEmail: String? = null,

    val brandName: String = "AuthAndSecurity",
) {
    val configured: Boolean get() = !clientId.isNullOrBlank() && !clientSecret.isNullOrBlank()
}

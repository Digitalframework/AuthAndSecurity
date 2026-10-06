package com.inigo.AuthAndSecurity.payment

import java.math.BigDecimal

/**
 * What can be bought, and for how much.
 *
 * An enum rather than anything the request carries: the caller sends a pack name,
 * never a price or a token count. If the amount came off the wire, a million
 * tokens for a cent would be a matter of editing the form before submitting it.
 */
enum class TokenPack(val tokens: Int, val price: BigDecimal) {
    SMALL(100, BigDecimal("4.99")),
    MEDIUM(500, BigDecimal("19.99")),
    LARGE(1200, BigDecimal("39.99")),
    ;

    /** As PayPal wants it: a decimal string with two places. */
    fun amountValue(): String = price.setScale(2).toPlainString()
}

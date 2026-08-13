package com.inigo.AuthAndSecurity.entity

import com.inigo.AuthAndSecurity.payment.TokenPack
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Index
import jakarta.persistence.Table
import java.math.BigDecimal
import java.time.Instant
import java.util.UUID

/**
 * One attempt to buy tokens through PayPal.
 *
 * Written *before* the visitor leaves for PayPal, which is what makes the trip
 * back verifiable: the return leg carries nothing but an order id, and this row is
 * what says whose order it was and what it was meant to cost. Neither is asked of
 * the returning request, because a redirect the visitor's browser performs is
 * entirely under their control.
 *
 * [creditedAt] is the single-use latch — without it the return URL would be a
 * token faucet, being a plain GET that can be replayed by pasting it back in.
 *
 * Properties are `var` because Hibernate has to populate them when it reads a row
 * back.
 */
@Entity
@Table(
    name = "token_purchase",
    indexes = [
        Index(name = "idx_token_purchase_order_id", columnList = "paypal_order_id", unique = true),
        Index(name = "idx_token_purchase_user_id", columnList = "user_id"),
    ],
)
class TokenPurchase(

    /** Taken from the session that started the purchase, never from a request parameter. */
    @Column(name = "user_id", nullable = false)
    var userId: UUID,

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    var pack: TokenPack,

    /** Copied off [pack] rather than looked up again later, so repricing cannot change an open purchase. */
    @Column(nullable = false)
    var tokens: Int,

    @Column(nullable = false, precision = 12, scale = 2)
    var amount: BigDecimal,

    @Column(nullable = false, length = 3)
    var currency: String,

    @Column(name = "paypal_order_id", nullable = false, unique = true, length = 64)
    var paypalOrderId: String,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant,

    /** Set once, and only after PayPal itself has confirmed the order. `null` means still open. */
    @Column(name = "credited_at")
    var creditedAt: Instant? = null,

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "purchase_id")
    var purchaseId: UUID? = null,
)

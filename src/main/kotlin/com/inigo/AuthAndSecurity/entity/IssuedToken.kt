package com.inigo.AuthAndSecurity.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Index
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

/**
 * A one-time sign-in token issued to an email address.
 *
 * Only a hash of the token is stored, so a leaked database dump does not hand
 * anyone a working login: the plaintext exists in memory just long enough to be
 * emailed. The hash is an unsalted SHA-256 rather than a password KDF, and that
 * is deliberate on two counts. Redemption arrives with nothing but the token, so
 * the row has to be found *by* its hash — a salted digest could not be looked up.
 * And a KDF's slowness buys nothing here: it exists to make guessing expensive,
 * and there are 2^256 tokens to guess from.
 *
 * Properties are `var` because Hibernate has to populate them when it reads a row
 * back.
 */
@Entity
@Table(
    name = "issued_token",
    indexes = [
        Index(name = "idx_issued_token_hash", columnList = "token_hash", unique = true),
        Index(name = "idx_issued_token_email_created_at", columnList = "email, created_at"),
    ],
)
class IssuedToken(

    @Column(nullable = false)
    var email: String,

    /** Hex-encoded SHA-256 of the token value that was emailed. */
    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    var tokenHash: String,

    @Column(nullable = false)
    var createdAt: Instant,

    @Column(nullable = false)
    var expiresAt: Instant,

    /**
     * When the token stopped being usable, for either of two reasons: it was
     * redeemed, or a newer token for the same address replaced it. `null` means
     * the token is still live.
     */
    var invalidatedAt: Instant? = null,

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    var id: UUID? = null,
)
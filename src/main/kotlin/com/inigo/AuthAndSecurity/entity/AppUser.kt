package com.inigo.AuthAndSecurity.entity

import jakarta.persistence.CollectionTable
import jakarta.persistence.Column
import jakarta.persistence.ElementCollection
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.FetchType
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Index
import jakarta.persistence.JoinColumn
import jakarta.persistence.Table
import java.time.Instant
import java.time.LocalDate
import java.util.UUID

/**
 * A registered user.
 *
 * A row appears the moment someone submits the registration form, with
 * [verifiedAt] still null: at that point nothing has been proved except that
 * somebody typed the address. Redeeming the emailed token is what sets
 * [verifiedAt], and only a verified row can be signed in to afterwards — see
 * [com.inigo.AuthAndSecurity.services.UserRegistrationService].
 *
 * Keeping the unverified row rather than parking the details somewhere separate
 * is what lets a half-finished registration be resumed by simply filling the form
 * in again: the same row is updated and a fresh link goes out.
 *
 * Properties are `var` because Hibernate has to populate them when it reads a row
 * back.
 */
@Entity
@Table(
    name = "app_user",
    indexes = [Index(name = "idx_app_user_email", columnList = "email", unique = true)],
)
class AppUser(

    /**
     * Normalized to lower case before it ever gets here, because it is also the
     * username the login resolves against and `Sam@` and `sam@` are one mailbox.
     */
    @Column(nullable = false, unique = true, length = 254)
    var email: String,

    @Column(nullable = false, length = 100)
    var firstname: String,

    @Column(nullable = false, length = 100)
    var surname: String,

    @Column(nullable = false)
    var dateOfBirth: LocalDate,

    /**
     * A table of its own rather than a single column, so a user can hold more than
     * one. Stored by name: an ordinal would tie the rows to the declaration order
     * of [Permission].
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "app_user_permission",
        joinColumns = [JoinColumn(name = "user_id")],
    )
    @Enumerated(EnumType.STRING)
    @Column(name = "permission", nullable = false, length = 32)
    var permissions: MutableSet<Permission> = mutableSetOf(Permission.USER),

    @Column(nullable = false)
    var createdAt: Instant,

    /**
     * When the emailed token was redeemed. `null` means the registration was
     * started but never confirmed, and such a row cannot be signed in to.
     */
    var verifiedAt: Instant? = null,

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id")
    var userId: UUID? = null,
) {
    val verified: Boolean get() = verifiedAt != null
}

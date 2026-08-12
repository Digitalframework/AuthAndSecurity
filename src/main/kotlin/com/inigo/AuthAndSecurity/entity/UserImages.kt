package com.inigo.AuthAndSecurity.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Index
import jakarta.persistence.Table
import java.util.UUID

/**
 * A single saved furniture picture, with the style that goes with it.
 *
 * [userId] is a plain column rather than a `@ManyToOne` to [AppUser], in keeping
 * with the rest of this schema (see [IssuedToken.email]): nothing here ever needs
 * to walk from a preference back to the user's other fields, and every access
 * already goes through [com.inigo.AuthAndSecurity.services.UserImagesService],
 * which is what keeps one visitor from ever reading or touching another's row —
 * not a foreign key.
 */
@Entity
@Table(
    name = "user_preference",
    indexes = [Index(name = "idx_user_preference_user_id", columnList = "user_id")],
)
class UserImages(

    @Column(name = "user_id", nullable = false)
    var userId: UUID,

    /**
     * Exactly 1024x1024, enforced in
     * [com.inigo.AuthAndSecurity.services.UserImagesService] rather than here —
     * an entity has no way to reject a write, only to shape the column it lands in.
     *
     * Plain `bytea` rather than `@Lob`: on PostgreSQL, `@Lob` on a byte array maps
     * to the large-object (`oid`) mechanism instead of an inline `bytea` column,
     * which needs a different read/write path than a normal JDBC byte array.
     * Leaving `@Lob` off gets the inline column this is meant to be.
     */
    @Column(name = "saved_picture", nullable = false, columnDefinition = "bytea")
    var savedPicture: ByteArray,

    /** What [savedPicture] was uploaded as, so it can be served back with the right header. */
    @Column(name = "picture_content_type", nullable = false, length = 100)
    var pictureContentType: String,

    @Column(nullable = false, length = 100)
    var style: String,

    @Column(nullable = false)
    var favorite: Boolean = false,

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "preference_id")
    var preferenceId: UUID? = null,
)

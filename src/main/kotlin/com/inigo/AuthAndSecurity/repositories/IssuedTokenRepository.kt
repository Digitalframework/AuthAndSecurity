package com.inigo.AuthAndSecurity.repositories

import com.inigo.AuthAndSecurity.entity.IssuedToken
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.time.Instant
import java.util.UUID

interface IssuedTokenRepository : JpaRepository<IssuedToken, UUID> {

    /**
     * The row a redemption is checked against. Redemption presents only the token,
     * so the hash is the sole handle onto the address it was issued to.
     */
    fun findByTokenHash(tokenHash: String): IssuedToken?

    /** Used for the resend cooldown, so it deliberately ignores invalidation. */
    fun findFirstByEmailOrderByCreatedAtDesc(email: String): IssuedToken?

    fun countByEmailAndCreatedAtAfter(email: String, since: Instant): Long

    /**
     * `clearAutomatically` is what makes the retirement stick. A bulk JPQL update
     * goes straight to the database and leaves the persistence context untouched,
     * so a token loaded earlier in the same transaction would still be sitting in
     * the first-level cache with `invalidatedAt` null — and would still redeem.
     * `flushAutomatically` pairs with it so a token saved but not yet flushed is
     * not skipped by the update.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update IssuedToken t set t.invalidatedAt = :now where t.email = :email and t.invalidatedAt is null")
    fun invalidateLiveTokensFor(@Param("email") email: String, @Param("now") now: Instant): Int

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from IssuedToken t where t.createdAt < :cutoff")
    fun deleteCreatedBefore(@Param("cutoff") cutoff: Instant): Int
}
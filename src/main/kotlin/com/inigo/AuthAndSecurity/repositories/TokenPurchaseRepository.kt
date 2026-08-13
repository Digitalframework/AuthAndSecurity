package com.inigo.AuthAndSecurity.repositories

import com.inigo.AuthAndSecurity.entity.TokenPurchase
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.time.Instant
import java.util.UUID

interface TokenPurchaseRepository : JpaRepository<TokenPurchase, UUID> {

    /**
     * Scoped to the owner in the query rather than checked afterwards: someone
     * else's order id simply finds nothing, the same as an id that was never real.
     */
    fun findByPaypalOrderIdAndUserId(paypalOrderId: String, userId: UUID): TokenPurchase?

    /**
     * Closes the single-use latch, returning 1 for the request that won and 0 for
     * every other. A conditional `UPDATE` rather than a read followed by a write,
     * because the latter has a window in which two requests both see `null` and
     * both hand out tokens.
     */
    @Modifying
    @Query(
        """
        update TokenPurchase p
           set p.creditedAt = :now
         where p.purchaseId = :purchaseId
           and p.creditedAt is null
        """
    )
    fun claim(@Param("purchaseId") purchaseId: UUID, @Param("now") now: Instant): Int
}

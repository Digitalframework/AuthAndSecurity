package com.inigo.AuthAndSecurity.repositories

import com.inigo.AuthAndSecurity.entity.AppUser
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.util.UUID

interface AppUserRepository : JpaRepository<AppUser, UUID> {

    /** [email] is always the normalized form; see [AppUser.email]. */
    fun findByEmail(email: String): AppUser?

    /**
     * Whether an address may be sent a *sign-in* link. Unverified rows are excluded
     * deliberately: a registration that was never confirmed is not an account yet,
     * and letting one be signed in to would make the confirmation step optional.
     */
    fun existsByEmailAndVerifiedAtIsNotNull(email: String): Boolean

    /**
     * Debits [amount], but only from a balance that still covers it. Returns 1 when
     * the debit happened and 0 when it did not — either the row is gone or the
     * balance was too low, which the caller tells apart.
     *
     * A conditional `UPDATE` for the same reason
     * [TokenPurchaseRepository.claim] is one: read-then-write leaves a window in
     * which two concurrent spends both see enough balance and the account goes
     * negative. The `where` clause is what makes the check and the debit one step.
     *
     * `clearAutomatically` because a bulk update goes straight to the database and
     * leaves any already-loaded [AppUser] in the persistence context holding the old
     * balance — reading it back afterwards would report the figure from before the
     * spend.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
        """
        update AppUser u
           set u.tokenBalance = u.tokenBalance - :amount
         where u.userId = :userId
           and u.tokenBalance >= :amount
        """
    )
    fun spendTokens(@Param("userId") userId: UUID, @Param("amount") amount: Int): Int
}

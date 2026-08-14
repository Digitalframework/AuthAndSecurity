package com.inigo.AuthAndSecurity.dto

import jakarta.validation.constraints.Min

/**
 * How many tokens to debit.
 *
 * Note what is *not* here: whose balance to take them from. That comes from the
 * subject of the verified token and nowhere else — a caller that could name the
 * owner could empty somebody else's account.
 */
data class SpendTokensRequest(

    /**
     * Positive, and validated rather than merely documented: a negative amount would
     * run the debit backwards and mint tokens out of a spend.
     */
    @field:Min(1)
    val amount: Int,
)

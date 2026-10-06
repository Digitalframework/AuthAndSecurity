package com.inigo.AuthAndSecurity.dto

/**
 * What the token endpoints report back, and the only thing they report: the balance
 * after whatever the call did. A spend returns it too, so a caller never has to
 * follow one with a read to find out where it stands.
 */
data class TokenBalanceResponse(val tokenBalance: Int)

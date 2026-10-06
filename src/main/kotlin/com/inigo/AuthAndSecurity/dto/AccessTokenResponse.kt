package com.inigo.AuthAndSecurity.dto

/**
 * A freshly minted access token, as `/api/token` hands it out.
 *
 * Shaped like an OAuth2 token response so a caller can treat it the way it would
 * treat any other — `Authorization: Bearer $accessToken`.
 */
data class AccessTokenResponse(

    /** The signed JWT itself. */
    val accessToken: String,

    /** How to present it. Constant, but callers copy it rather than hard-code it. */
    val tokenType: String = "Bearer",

    /**
     * Seconds of life left. A relative figure rather than an absolute instant
     * because it needs no agreement about clocks to be acted on — a caller can
     * refresh a little before it runs out without knowing what time this server
     * thinks it is.
     */
    val expiresIn: Long,

    /**
     * What the token says the holder may do, e.g. `["ADMIN", "USER"]`. Purely so a
     * UI can hide what would be refused anyway; the authority is the `roles` claim
     * inside the token, which is signed, and this field is not.
     */
    val roles: List<String>,
)

package com.inigo.AuthAndSecurity.dto

import java.util.UUID

/**
 * A saved furniture entry as the API reports it. The picture itself is not in
 * here — [pictureUrl] points at the endpoint that serves the raw bytes instead,
 * so that listing many entries stays cheap.
 */
data class UserPreferenceResponse(
    val id: UUID,
    val style: String,
    val favorite: Boolean,
    val pictureUrl: String,
)

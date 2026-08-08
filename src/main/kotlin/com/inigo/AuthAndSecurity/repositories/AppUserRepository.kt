package com.inigo.AuthAndSecurity.repositories

import com.inigo.AuthAndSecurity.entity.AppUser
import org.springframework.data.jpa.repository.JpaRepository
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
}

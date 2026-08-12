package com.inigo.AuthAndSecurity.repositories

import com.inigo.AuthAndSecurity.entity.UserPreference
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface UserPreferenceRepository : JpaRepository<UserPreference, UUID> {

    fun findAllByUserId(userId: UUID): List<UserPreference>

    /**
     * Scoped to the owner in the query itself, not checked afterwards — so a
     * lookup by another visitor's preference id simply finds nothing, the same
     * shape of answer as an id that does not exist at all.
     */
    fun findByPreferenceIdAndUserId(preferenceId: UUID, userId: UUID): UserPreference?

    fun deleteByPreferenceIdAndUserId(preferenceId: UUID, userId: UUID): Long
}

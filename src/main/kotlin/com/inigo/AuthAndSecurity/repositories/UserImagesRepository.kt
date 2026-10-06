package com.inigo.AuthAndSecurity.repositories

import com.inigo.AuthAndSecurity.entity.UserImages
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface UserImagesRepository : JpaRepository<UserImages, UUID> {

    fun findAllByUserId(userId: UUID): List<UserImages>

    /**
     * Scoped to the owner in the query itself, not checked afterwards — so a
     * lookup by another visitor's preference id simply finds nothing, the same
     * shape of answer as an id that does not exist at all.
     */
    fun findByPreferenceIdAndUserId(preferenceId: UUID, userId: UUID): UserImages?

    fun deleteByPreferenceIdAndUserId(preferenceId: UUID, userId: UUID): Long
}

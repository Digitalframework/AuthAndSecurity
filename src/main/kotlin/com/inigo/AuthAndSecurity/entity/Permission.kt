package com.inigo.AuthAndSecurity.entity

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority

/**
 * What a registered user is allowed to do.
 *
 * Stored by name rather than ordinal (see [AppUser.permissions]), so inserting a
 * value between these two later does not silently repoint every existing row.
 */
enum class Permission {

    /** Everything a plain account gets. Granted to every registration. */
    USER,

    /** Never granted by registering; an existing row has to be given it. */
    ADMIN,
    ;

    /**
     * Spring Security's `hasRole("ADMIN")` looks for the authority `ROLE_ADMIN`,
     * so the prefix is added here rather than being spelled into the enum names.
     */
    val authority: GrantedAuthority = SimpleGrantedAuthority("ROLE_$name")
}

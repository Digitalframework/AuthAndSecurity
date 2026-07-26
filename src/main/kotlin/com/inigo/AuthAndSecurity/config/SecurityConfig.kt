package com.inigo.AuthAndSecurity.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize("/", permitAll)
                authorize("/index.html", permitAll)
                authorize("/favicon.ico", permitAll)
                authorize("/error", permitAll)
                // Public so the landing page can ask whether anyone is signed in.
                authorize("/api/me", permitAll)
                authorize("/api/csrf", permitAll)
                authorize(anyRequest, authenticated)
            }
            // Google is the only registered client, so Spring sends unauthenticated
            // users straight to it instead of rendering a provider-picker page.
            oauth2Login { }
            logout {
                logoutSuccessUrl = "/"
            }
        }
        return http.build()
    }
}
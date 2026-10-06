package com.inigo.AuthAndSecurity.config

import com.inigo.AuthAndSecurity.controller.JwkSetController
import com.inigo.AuthAndSecurity.controller.UserController
import com.inigo.AuthAndSecurity.onetimetoken.EmailOneTimeTokenGenerationSuccessHandler
import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenProperties
import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenRateLimitFilter
import com.inigo.AuthAndSecurity.onetimetoken.RegistrationCompletingSuccessHandler
import com.inigo.AuthAndSecurity.onetimetoken.SignInLinkBuilder
import com.inigo.AuthAndSecurity.services.EmailService
import com.inigo.AuthAndSecurity.services.OneTimeTokenRateLimiterService
import com.inigo.AuthAndSecurity.services.PersistentOneTimeTokenService
import com.inigo.AuthAndSecurity.services.RegisteredUserDetailsService
import com.inigo.AuthAndSecurity.services.UserRegistrationService
import com.inigo.AuthAndSecurity.services.AccessTokenService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationProvider
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.ott.DefaultGenerateOneTimeTokenRequestResolver
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import java.time.Clock

@Configuration
@EnableWebSecurity
// Turns on the @PreAuthorize annotations guarding the token endpoints. Without it
// they are ignored silently, with nothing said at startup — the same trap
// generation-backend's SecurityConfig notes.
@EnableMethodSecurity
class SecurityConfig {

    /**
     * The endpoints generation-backend calls with the token [AccessTokenService]
     * minted for it, kept on a chain of their own.
     *
     * Separate rather than a few more rules on the chain below, because almost
     * nothing about them is the same. That one is for a browser: it carries a session
     * cookie, wants CSRF protection, and answers an unauthenticated request with a
     * redirect to the login page. A service holding a bearer token wants none of
     * those — least of all the redirect, which would hand it a 302 and an HTML login
     * form where it expected a 401 and JSON.
     *
     * Ordered first because the chain below matches every request that reaches it, so
     * whichever is registered earlier wins these two paths.
     */
    @Bean
    @Order(1)
    fun tokenApiSecurityFilterChain(http: HttpSecurity, decoder: JwtDecoder): SecurityFilterChain {
        http {
            securityMatcher(UserController.BALANCE_URL, UserController.SPEND_URL)
            // No cookie is read on this chain, so there is no ambient credential for a
            // forged cross-site request to ride on — which is the only thing a CSRF
            // token defends. A bearer token has to be attached deliberately.
            csrf { disable() }
            sessionManagement { sessionCreationPolicy = SessionCreationPolicy.STATELESS }
            formLogin { disable() }
            httpBasic { disable() }
            authorizeHttpRequests {
                // Only "is this anyone at all" here; which role may do what is on the
                // controller methods, next to the code it protects.
                authorize(anyRequest, authenticated)
            }
            oauth2ResourceServer {
                jwt { jwtAuthenticationConverter = rolesAuthenticationConverter() }
            }
        }
        return http.build()
    }

    /**
     * Maps the token's `roles` claim onto authorities, the mirror image of what
     * [AccessTokenService] wrote and a copy of what generation-backend does with the
     * same tokens.
     *
     * Both defaults have to be overridden and both fail silently: Spring reads
     * `scope`/`scp`, which these tokens do not carry, and prefixes with `SCOPE_`,
     * while `hasRole('USER')` tests for exactly `ROLE_USER`. Get either wrong and the
     * caller simply arrives with no authorities and is refused by a 403 that explains
     * nothing.
     */
    private fun rolesAuthenticationConverter(): JwtAuthenticationConverter {
        val authorities = JwtGrantedAuthoritiesConverter()
        authorities.setAuthoritiesClaimName(AccessTokenService.ROLES_CLAIM)
        authorities.setAuthorityPrefix("ROLE_")

        return JwtAuthenticationConverter().apply { setJwtGrantedAuthoritiesConverter(authorities) }
    }

    @Bean
    @Order(2)
    fun securityFilterChain(
        http: HttpSecurity,
        tokenService: PersistentOneTimeTokenService,
        userDetailsService: RegisteredUserDetailsService,
        rateLimiter: OneTimeTokenRateLimiterService,
        emailService: EmailService,
        linkBuilder: SignInLinkBuilder,
        registrations: UserRegistrationService,
        properties: OneTimeTokenProperties,
        clock: Clock,
    ): SecurityFilterChain {
        val generateMatcher =
            PathPatternRequestMatcher.pathPattern(HttpMethod.POST, OneTimeTokenRateLimitFilter.GENERATE_URL)

        // Spring's resolver defaults to a five-minute expiry of its own, so the
        // configured TTL has to be pushed onto it rather than read downstream.
        val requestResolver = DefaultGenerateOneTimeTokenRequestResolver()
        requestResolver.setExpiresIn(properties.ttl)

        http {
            // Neither is applied by default to a chain built this way, but saying so
            // outright keeps a later edit from quietly reintroducing a password path
            // into an application that has no passwords to check.
            formLogin { disable() }
            httpBasic { disable() }
            authorizeHttpRequests {
                authorize(OneTimeTokenRateLimitFilter.LOGIN_URL, permitAll)
                // Signing up is necessarily open: the whole point is that whoever
                // reaches it has no account yet.
                authorize(OneTimeTokenRateLimitFilter.REGISTER_URL, permitAll)
                authorize(OneTimeTokenRateLimitFilter.GENERATE_URL, permitAll)
                authorize(OneTimeTokenRateLimitFilter.SENT_URL, permitAll)
                // Both the page that takes a pasted token and the POST that spends
                // it — an unauthenticated caller is the only kind there is here.
                authorize(EmailOneTimeTokenGenerationSuccessHandler.SUBMIT_PATH, permitAll)
                // The public half of the token-signing key. Open because a verifier
                // fetches it before it has any token to present, and because a public
                // key is not a secret — see JwkSetController.
                authorize(JwkSetController.JWK_SET_PATH, permitAll)
                authorize("/css/**", permitAll)
                authorize("/favicon.ico", permitAll)
                authorize("/error", permitAll)
                authorize(anyRequest, authenticated)
            }
            oneTimeTokenLogin {
                tokenGeneratingUrl = OneTimeTokenRateLimitFilter.GENERATE_URL
                loginProcessingUrl = EmailOneTimeTokenGenerationSuccessHandler.SUBMIT_PATH
                oneTimeTokenGenerationSuccessHandler =
                    EmailOneTimeTokenGenerationSuccessHandler(emailService, linkBuilder, clock)
                generateRequestResolver = requestResolver
                // Redeeming a token is what proves the address, so it is also what
                // turns a pending registration into a real account. Wraps the
                // redirect Spring would have used, rather than replacing it.
                authenticationSuccessHandler = RegistrationCompletingSuccessHandler(registrations)
                // A page of this application's own is served at that URL instead,
                // so the framework's generated one would only shadow it.
                showDefaultSubmitPage = false
                // Otherwise a rejected token bounces back to the submit page, which
                // would re-offer the very token that just failed.
                authenticationFailureHandler =
                    SimpleUrlAuthenticationFailureHandler("${OneTimeTokenRateLimitFilter.LOGIN_URL}?error=invalid")
                // Named explicitly so the provider is built against this
                // application's token store and principal lookup rather than
                // whatever single UserDetailsService happens to be in the context.
                authenticationProvider = OneTimeTokenAuthenticationProvider(tokenService, userDetailsService)
            }
            // Two ways in, so unauthenticated requests land on the page that offers
            // both instead of being bounced straight to Google.
            oauth2Login {
                loginPage = OneTimeTokenRateLimitFilter.LOGIN_URL
            }
            logout {
                logoutSuccessUrl = OneTimeTokenRateLimitFilter.LOGIN_URL
            }
        }

        // Says that this application serves its own /login. Without it Spring
        // Security keeps DefaultLoginPageGeneratingFilter enabled and answers /login
        // with its own generated "Request a One-Time Token" form, which shadows
        // LoginPageController and offers no way to reach Google. Set on the
        // configurer directly because OneTimeTokenLoginDsl — unlike the Java
        // configurer it wraps — exposes no loginPage property. The same instance the
        // DSL above configured is returned here, so this only adds to it.
        http.oneTimeTokenLogin { it.loginPage(OneTimeTokenRateLimitFilter.LOGIN_URL) }

        // Ahead of the filter that mints tokens, so a refused request never reaches
        // it. Registered outside the DSL because the one-time-token configurer has
        // no hook of its own for this.
        http.addFilterBefore(
            OneTimeTokenRateLimitFilter(rateLimiter, generateMatcher),
            GenerateOneTimeTokenFilter::class.java,
        )

        return http.build()
    }
}
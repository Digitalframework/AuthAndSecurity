package com.inigo.AuthAndSecurity.config

import com.inigo.AuthAndSecurity.onetimetoken.OneTimeTokenProperties
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.mail.autoconfigure.MailProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.scheduling.annotation.EnableAsync
import org.springframework.scheduling.annotation.EnableScheduling
import com.inigo.AuthAndSecurity.services.EmailService
import com.inigo.AuthAndSecurity.services.LoggingEmailService
import com.inigo.AuthAndSecurity.services.SmtpEmailService
import java.time.Clock

@Configuration
@EnableScheduling
@EnableAsync
class OneTimeTokenConfig {

    private val log = LoggerFactory.getLogger(javaClass)

    /** Injected rather than called statically so tests can wind time forward. */
    @Bean
    fun clock(): Clock = Clock.systemUTC()

    /**
     * Spring Boot only auto-configures a [org.springframework.mail.javamail.JavaMailSender] when `spring.mail.host`
     * is set, so its absence is what selects the log-only sender for local runs.
     */
    @Bean
    fun emailService(
        mailSender: ObjectProvider<JavaMailSender>,
        mailProperties: ObjectProvider<MailProperties>,
        properties: OneTimeTokenProperties,
    ): EmailService {
        val smtp = mailSender.getIfAvailable()
        if (smtp == null) {
            log.warn(
                "spring.mail.host is not set: sign-in links will be written to this log instead of " +
                    "being emailed. Fine for local development, never for anything else."
            )
            return LoggingEmailService()
        }
        val from = properties.from ?: mailProperties.getIfAvailable()?.username
        return SmtpEmailService(smtp, from)
    }
}
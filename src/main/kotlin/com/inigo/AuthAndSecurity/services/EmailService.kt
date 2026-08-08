package com.inigo.AuthAndSecurity.services

import org.slf4j.LoggerFactory
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.mail.javamail.MimeMessageHelper
import org.springframework.scheduling.annotation.Async
import java.time.Duration

/** Delivers a freshly minted sign-in link to its owner. */
interface EmailService {

    /**
     * Sends [link] to [email]. Implementations are asynchronous, so a failure
     * surfaces in the log rather than to the caller — see [SmtpEmailService] for
     * why that trade is made here.
     */
    fun sendSignInLink(email: String, link: String, token: String, validFor: Duration)
}

class SmtpEmailService(
    private val mailSender: JavaMailSender,
    private val from: String?,
) : EmailService {

    private val log = LoggerFactory.getLogger(javaClass)

    /**
     * Off the request thread, because an SMTP handshake is far slower than
     * everything else in the sign-in path and the user has nothing to wait for:
     * the token row is already committed, so the link works whether or not the
     * message has been handed over yet.
     *
     * The cost of that is real, and it is the reverse of what the six-digit code
     * flow did — that one sent inside the transaction so a rejected message rolled
     * the code back. Here a bounced message leaves a usable token behind that
     * nobody receives, and the user simply sees the confirmation page and no
     * email. The resend cooldown is what lets them recover.
     */
    @Async
    override fun sendSignInLink(email: String, link: String, token: String, validFor: Duration) {
        try {
            val message = mailSender.createMimeMessage()
            val helper = MimeMessageHelper(message, true, "UTF-8")
            from?.let { helper.setFrom(it) }
            helper.setTo(email)
            // The token stays out of the subject line: subjects show up in
            // mail-server logs and notification previews far more readily than
            // bodies do.
            helper.setSubject("Your sign-in link")
            helper.setText(plainTextBody(link, token, validFor), htmlBody(link, token, validFor))
            mailSender.send(message)
        } catch (ex: Exception) {
            // Nothing downstream can act on this — the caller returned long ago —
            // so it is logged and dropped. The address is included; the token is
            // not.
            log.error("Could not email a sign-in link to {}", email, ex)
        }
    }

    private fun plainTextBody(link: String, token: String, validFor: Duration): String =
        """
        Use this link to sign in:

            $link

        If the link does not open, paste this code into the sign-in page instead:

            $token

        It expires in ${validFor.toMinutes()} minutes and works only once.

        If you did not try to sign in, you can ignore this email — whoever asked
        for the link cannot do anything without it.
        """.trimIndent()

    private fun htmlBody(link: String, token: String, validFor: Duration): String =
        """
        <!doctype html>
        <html lang="en">
        <body style="margin:0;padding:24px;font:16px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;color:#1a1a1a;">
          <p>Use this link to sign in:</p>
          <p>
            <a href="${escapeHtml(link)}"
               style="display:inline-block;padding:12px 20px;border-radius:8px;background:#1a1a1a;color:#fff;text-decoration:none;">
              Sign in
            </a>
          </p>
          <p style="color:#666;font-size:14px;">
            If the button does not work, paste this code into the sign-in page:
          </p>
          <p style="font-family:ui-monospace,monospace;font-size:14px;word-break:break-all;">${escapeHtml(token)}</p>
          <p style="color:#666;font-size:14px;">
            It expires in ${validFor.toMinutes()} minutes and works only once.
          </p>
          <p style="color:#666;font-size:14px;">
            If you did not try to sign in, you can ignore this email &mdash; whoever
            asked for the link cannot do anything without it.
          </p>
        </body>
        </html>
        """.trimIndent()

    /**
     * The link and token are values this application generated, not user input,
     * but they are interpolated into markup all the same and escaping them costs
     * nothing.
     */
    private fun escapeHtml(value: String): String = value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
}

/**
 * Fallback used when no SMTP server is configured, so the flow can be exercised
 * locally without one. Writing sign-in links to the log is obviously not something
 * to run anywhere real, hence the WARN level on every single send.
 */
class LoggingEmailService : EmailService {

    private val log = LoggerFactory.getLogger(javaClass)

    override fun sendSignInLink(email: String, link: String, token: String, validFor: Duration) {
        log.warn(
            "No SMTP server configured, so nothing was emailed. Sign-in link for {} is {} (valid {} minutes). " +
                "Set spring.mail.host to deliver links for real.",
            email,
            link,
            validFor.toMinutes(),
        )
    }
}
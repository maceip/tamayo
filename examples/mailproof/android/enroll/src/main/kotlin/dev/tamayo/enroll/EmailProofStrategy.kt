package dev.tamayo.enroll

/**
 * How the verification email travels. Offer the strategies that make sense
 * for your app; the overlay presents whatever you pass it.
 */
sealed interface EmailProofStrategy {
    /**
     * Open the user's mail app with a prefilled message to the verify
     * address; the user presses send themselves. Zero permissions needed,
     * and the message sits in their own Sent folder afterwards — the whole
     * disclosure is auditable by the user.
     */
    data object MailtoCompose : EmailProofStrategy

    /**
     * The integrating app sends the message itself — the right choice for
     * apps that already speak SMTP on the user's behalf (mail clients like
     * SigBird). The lambda gets (to, subject, body) and must submit the
     * message from the user's own address.
     */
    class AppSends(
        val send: suspend (to: String, subject: String, body: String) -> Unit,
    ) : EmailProofStrategy

    /**
     * Reverse direction: the issuer emails a 6-digit code to the address
     * the user types, and the user echoes it back. Requires the issuer
     * deployment to have an outbound relay, but needs no inbound mail at
     * all on the issuer side... and no mail app on the device.
     */
    data object CodeToInbox : EmailProofStrategy
}

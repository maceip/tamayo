package dev.tamayo.enroll

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import kotlinx.coroutines.launch

private sealed interface OverlayState {
    data object Choose : OverlayState
    data class AwaitingEmail(val session: EnrollClient.SendSession, val viaMailto: Boolean) : OverlayState
    data object CodeEmailEntry : OverlayState
    data class CodeEntry(val session: EnrollClient.CodeSession, val email: String) : OverlayState
    data object Minting : OverlayState
    data class Failed(val message: String) : OverlayState
}

/**
 * Drop-in enrollment flow: "this app needs a token — prove a mailbox, get
 * one, no account created". Shows the strategies you offer, walks the user
 * through the proof, and hands back a [MintedToken].
 */
@Composable
fun EnrollOverlay(
    client: EnrollClient,
    strategies: List<EmailProofStrategy>,
    onToken: (MintedToken) -> Unit,
    onDismiss: () -> Unit,
) {
    var state by remember { mutableStateOf<OverlayState>(OverlayState.Choose) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    fun fail(t: Throwable) {
        state = OverlayState.Failed(t.message ?: "something went wrong")
    }

    fun mint(sessionId: String) {
        state = OverlayState.Minting
        scope.launch {
            try {
                onToken(client.mint(sessionId))
                onDismiss()
            } catch (t: Exception) {
                fail(t)
            }
        }
    }

    fun startSendFlow(strategy: EmailProofStrategy) {
        scope.launch {
            try {
                val session = client.startSendSession()
                val body = "This message proves mailbox control for a one-time token. " +
                    "Only a salted hash of your address reaches the issuer; the token itself carries no address."
                when (strategy) {
                    is EmailProofStrategy.MailtoCompose -> {
                        state = OverlayState.AwaitingEmail(session, viaMailto = true)
                        val uri = Uri.parse(
                            "mailto:${session.verifyAddress}" +
                                "?subject=${Uri.encode(session.emailSubject)}" +
                                "&body=${Uri.encode(body)}",
                        )
                        context.startActivity(Intent(Intent.ACTION_SENDTO, uri))
                    }
                    is EmailProofStrategy.AppSends -> {
                        state = OverlayState.AwaitingEmail(session, viaMailto = false)
                        strategy.send(session.verifyAddress, session.emailSubject, body)
                    }
                    else -> error("unreachable")
                }
                if (client.awaitVerified(session.sessionId)) {
                    mint(session.sessionId)
                } else {
                    state = OverlayState.Failed("The verification email never arrived. Try again?")
                }
            } catch (t: Exception) {
                fail(t)
            }
        }
    }

    Dialog(onDismissRequest = onDismiss) {
        Card {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                when (val s = state) {
                    is OverlayState.Choose -> ChooseStep(
                        strategies = strategies,
                        onSend = { startSendFlow(it) },
                        onCode = { state = OverlayState.CodeEmailEntry },
                        onDismiss = onDismiss,
                    )

                    is OverlayState.AwaitingEmail -> {
                        Text("Waiting for your email", style = MaterialTheme.typography.titleMedium)
                        Text(
                            if (s.viaMailto) {
                                "Press send in your mail app. The message goes to " +
                                    "${s.session.verifyAddress} and stays in your Sent folder, " +
                                    "so you can always see exactly what was shared."
                            } else {
                                "Sending the verification email from your account…"
                            },
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        CircularProgressIndicator()
                    }

                    is OverlayState.CodeEmailEntry -> CodeEmailStep(
                        onSubmit = { email ->
                            scope.launch {
                                try {
                                    val session = client.startCodeSession()
                                    client.sendCode(session.sessionId, email)
                                    state = OverlayState.CodeEntry(session, email)
                                } catch (t: Exception) {
                                    fail(t)
                                }
                            }
                        },
                        onBack = { state = OverlayState.Choose },
                    )

                    is OverlayState.CodeEntry -> CodeEntryStep(
                        email = s.email,
                        onSubmit = { code ->
                            scope.launch {
                                try {
                                    client.verifyCode(s.session.sessionId, s.email, code)
                                    mint(s.session.sessionId)
                                } catch (t: Exception) {
                                    fail(t)
                                }
                            }
                        },
                    )

                    is OverlayState.Minting -> {
                        Text("Minting your token", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Generating a keypair on this device and asking the issuer to " +
                                "blind-sign the public half. No account is being created.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        CircularProgressIndicator()
                    }

                    is OverlayState.Failed -> {
                        Text("Enrollment failed", style = MaterialTheme.typography.titleMedium)
                        Text(s.message, style = MaterialTheme.typography.bodyMedium)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = { state = OverlayState.Choose }) { Text("Start over") }
                            TextButton(onClick = onDismiss) { Text("Close") }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ChooseStep(
    strategies: List<EmailProofStrategy>,
    onSend: (EmailProofStrategy) -> Unit,
    onCode: () -> Unit,
    onDismiss: () -> Unit,
) {
    Text("Get a token — no signup", style = MaterialTheme.typography.titleMedium)
    Text(
        "Prove you control a mailbox and this device mints an anonymous, " +
            "reusable pass. The service you use it at never learns your address.",
        style = MaterialTheme.typography.bodyMedium,
    )
    Spacer(Modifier.height(4.dp))
    strategies.forEach { strategy ->
        when (strategy) {
            is EmailProofStrategy.MailtoCompose -> Button(
                onClick = { onSend(strategy) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Send a verification email") }

            is EmailProofStrategy.AppSends -> Button(
                onClick = { onSend(strategy) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Verify with my account") }

            is EmailProofStrategy.CodeToInbox -> OutlinedButton(
                onClick = onCode,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Email me a code instead") }
        }
    }
    TextButton(onClick = onDismiss) { Text("Not now") }
}

@Composable
private fun CodeEmailStep(
    onSubmit: (String) -> Unit,
    onBack: () -> Unit,
) {
    var email by remember { mutableStateOf("") }
    Text("Where should the code go?", style = MaterialTheme.typography.titleMedium)
    Text(
        "The issuer emails a 6-digit code and keeps only a salted hash of the address.",
        style = MaterialTheme.typography.bodyMedium,
    )
    OutlinedTextField(
        value = email,
        onValueChange = { email = it },
        label = { Text("Email address") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { onSubmit(email.trim()) }, enabled = email.contains("@")) { Text("Send code") }
        TextButton(onClick = onBack) { Text("Back") }
    }
}

@Composable
private fun CodeEntryStep(
    email: String,
    onSubmit: (String) -> Unit,
) {
    var code by remember { mutableStateOf("") }
    Text("Enter the code", style = MaterialTheme.typography.titleMedium)
    Text("We sent a 6-digit code to $email.", style = MaterialTheme.typography.bodyMedium)
    OutlinedTextField(
        value = code,
        onValueChange = { code = it.filter(Char::isDigit).take(6) },
        label = { Text("6-digit code") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Button(onClick = { onSubmit(code) }, enabled = code.length == 6) { Text("Verify") }
}

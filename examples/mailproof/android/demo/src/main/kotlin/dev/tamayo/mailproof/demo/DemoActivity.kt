package dev.tamayo.mailproof.demo

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.tamayo.enroll.EmailProofStrategy
import dev.tamayo.enroll.EnrollClient
import dev.tamayo.enroll.EnrollOverlay
import dev.tamayo.enroll.MintedToken
import java.io.ByteArrayOutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

/**
 * The whole mailproof loop in one screen:
 *  1. Enroll: prove a mailbox to the issuer, mint a private-identity token.
 *  2. Spend: upload an image to the demo imagehost — a service that has
 *     never spoken to the issuer beyond fetching its public key, and that
 *     only ever sees an origin-bound pseudonym.
 */
class DemoActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val enrollClient = EnrollClient(BuildConfig.ISSUER_BASE)
        val http = OkHttpClient()

        setContent {
            var token by remember { mutableStateOf<MintedToken?>(null) }
            var overlayVisible by remember { mutableStateOf(false) }
            var log by remember { mutableStateOf("No token yet.") }
            val scope = rememberCoroutineScope()

            MaterialTheme {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    Text("Mailproof demo", style = MaterialTheme.typography.headlineSmall)
                    Text(log, style = MaterialTheme.typography.bodyMedium)

                    Button(
                        onClick = { overlayVisible = true },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = token == null,
                    ) { Text(if (token == null) "Get a token" else "Token minted") }

                    Button(
                        onClick = {
                            val t = token ?: return@Button
                            scope.launch {
                                log = try {
                                    val url = uploadTestImage(http, t)
                                    "Uploaded anonymously: $url"
                                } catch (e: Exception) {
                                    "Upload failed: ${e.message}"
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = token != null,
                    ) { Text("Upload an image with it") }
                }

                if (overlayVisible) {
                    EnrollOverlay(
                        client = enrollClient,
                        strategies = listOf(
                            EmailProofStrategy.MailtoCompose,
                            EmailProofStrategy.CodeToInbox,
                        ),
                        onToken = {
                            token = it
                            log = "Token minted. It contains no email address — " +
                                "check for yourself: ${it.tokenB64.take(48)}…"
                        },
                        onDismiss = { overlayVisible = false },
                    )
                }
            }
        }
    }

    /** Presents the token to the imagehost and uploads a generated PNG. */
    private suspend fun uploadTestImage(http: OkHttpClient, token: MintedToken): String =
        withContext(Dispatchers.IO) {
            val base = BuildConfig.IMAGEHOST_BASE.trimEnd('/')

            val challenge = http.postJson("$base/v1/challenges", JSONObject())
            val nonce = java.util.Base64.getUrlDecoder().decode(challenge.getString("nonce_b64"))
            val origin = challenge.getString("origin")

            val issuedAt = System.currentTimeMillis() / 1000L
            val signature = token.signPresentation(origin, nonce, issuedAt)

            val body = JSONObject()
                .put("token_b64", token.tokenB64)
                .put("nonce_b64", challenge.getString("nonce_b64"))
                .put("issued_at", issuedAt)
                .put(
                    "signature_b64",
                    java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signature),
                )
                .put("image_b64", java.util.Base64.getEncoder().encodeToString(testPng()))
                .put("content_type", "image/png")

            val resp = http.postJson("$base/v1/images", body)
            base + resp.getString("url")
        }

    private fun testPng(): ByteArray {
        val bitmap = Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888)
        Canvas(bitmap).drawColor(Color.rgb(64, 160, 96))
        val out = ByteArrayOutputStream()
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
        return out.toByteArray()
    }
}

private fun OkHttpClient.postJson(url: String, body: JSONObject): JSONObject {
    val request = Request.Builder()
        .url(url)
        .post(body.toString().toRequestBody("application/json".toMediaType()))
        .build()
    newCall(request).execute().use { response ->
        val text = response.body?.string().orEmpty()
        check(response.isSuccessful) { "POST $url failed: HTTP ${response.code} $text" }
        return JSONObject(text)
    }
}

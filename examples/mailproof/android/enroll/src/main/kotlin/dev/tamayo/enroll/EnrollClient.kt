package dev.tamayo.enroll

import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

/**
 * Client for the mailproof issuer (`services/issuerd`): email-verified,
 * zero-signup minting of tamayo private-identity tokens.
 *
 * Two proof directions are supported:
 *  - send: the user emails `verify+<session>@<issuer domain>` from the
 *    mailbox they want to prove. Works with a mailto: intent (the message
 *    lands in the user's own Sent folder, which is a feature — they can see
 *    exactly what was disclosed) or with an app that can send mail itself.
 *  - code: the issuer emails a 6-digit code to the address; the user types
 *    it back. Requires the issuer to have an outbound relay.
 *
 * The issuer only ever keeps an HMAC bucket of the address. The token that
 * comes back contains no address at all.
 */
class EnrollClient(
    baseUrl: String,
    private val httpClient: OkHttpClient = defaultClient(),
) {
    private val base = baseUrl.trimEnd('/')

    data class SendSession(
        val sessionId: String,
        val verifyAddress: String,
        val emailSubject: String,
        val expiresAtEpochSeconds: Long,
    )

    data class CodeSession(
        val sessionId: String,
        val expiresAtEpochSeconds: Long,
    )

    suspend fun startSendSession(): SendSession = withContext(Dispatchers.IO) {
        val resp = postJson("/v1/sessions", JSONObject().put("mode", "send"))
        SendSession(
            sessionId = resp.getString("session_id"),
            verifyAddress = resp.getString("verify_address"),
            emailSubject = resp.optString("email_subject", "verify"),
            expiresAtEpochSeconds = resp.getLong("expires_at"),
        )
    }

    suspend fun startCodeSession(): CodeSession = withContext(Dispatchers.IO) {
        val resp = postJson("/v1/sessions", JSONObject().put("mode", "code"))
        CodeSession(
            sessionId = resp.getString("session_id"),
            expiresAtEpochSeconds = resp.getLong("expires_at"),
        )
    }

    suspend fun isVerified(sessionId: String): Boolean = withContext(Dispatchers.IO) {
        getJson("/v1/sessions/$sessionId").getString("status") == "verified"
    }

    /**
     * Polls the session until the issuer has seen the verification email.
     * Returns true when verified, false on timeout.
     */
    suspend fun awaitVerified(
        sessionId: String,
        timeoutMillis: Long = 120_000L,
        pollMillis: Long = 2_000L,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            if (isVerified(sessionId)) return true
            delay(pollMillis)
        }
        return false
    }

    /** Code direction step 1: the issuer emails a 6-digit code to [email]. */
    suspend fun sendCode(sessionId: String, email: String) {
        withContext(Dispatchers.IO) {
            postJson("/v1/sessions/$sessionId/send-code", JSONObject().put("email", email))
        }
    }

    /** Code direction step 2: prove receipt by echoing the code. */
    suspend fun verifyCode(sessionId: String, email: String, code: String) {
        withContext(Dispatchers.IO) {
            postJson(
                "/v1/sessions/$sessionId/verify-code",
                JSONObject().put("email", email).put("code", code),
            )
        }
    }

    /**
     * Mints a private-identity token for a verified session. The Ed25519
     * holder keypair is generated here; only the public key is sent.
     */
    suspend fun mint(sessionId: String): MintedToken = withContext(Dispatchers.IO) {
        val seed = ByteArray(Wire.ED25519_SEED_BYTES).also { SecureRandom().nextBytes(it) }
        val holderPubB64 = Wire.b64Encode(Wire.ed25519PublicKey(seed))
        val resp = postJson(
            "/v1/sessions/$sessionId/mint",
            JSONObject().put("holder_pub_b64", holderPubB64),
        )
        check(!resp.has("holder_seed_b64")) { "issuer must never return a holder seed" }
        check(resp.getString("holder_pub_b64") == holderPubB64) { "issuer echoed a different holder key" }
        MintedToken(
            tokenBytes = Wire.b64Decode(resp.getString("token_b64")),
            holderSeed = seed,
        )
    }

    private fun postJson(path: String, body: JSONObject): JSONObject {
        val request = Request.Builder()
            .url(base + path)
            .post(body.toString().toRequestBody(JSON_MIME.toMediaType()))
            .build()
        return execute(request, "POST $path")
    }

    private fun getJson(path: String): JSONObject {
        val request = Request.Builder().url(base + path).get().build()
        return execute(request, "GET $path")
    }

    private fun execute(request: Request, what: String): JSONObject {
        httpClient.newCall(request).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw EnrollException("$what failed: HTTP ${response.code} $text")
            }
            return JSONObject(text)
        }
    }

    companion object {
        private const val JSON_MIME = "application/json"

        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .build()
    }
}

class EnrollException(message: String) : Exception(message)

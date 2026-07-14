package dev.tamayo.enroll

import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollClientTest {

    @Test
    fun `code direction walks session, send-code, verify-code, status`() = runTest {
        MockWebServer().use { server ->
            server.enqueue(
                json(
                    """{"session_id":"abc","mode":"code","status":"pending","expires_at":1700000900}""",
                ),
            )
            server.enqueue(json("""{"sent":true}"""))
            server.enqueue(json("""{"status":"verified"}"""))
            server.enqueue(json("""{"session_id":"abc","status":"verified","mode":"code","minted":false,"expires_at":1700000900}"""))
            server.start()
            val client = EnrollClient(server.url("/").toString())

            val session = client.startCodeSession()
            assertEquals("abc", session.sessionId)
            client.sendCode(session.sessionId, "bob@example.org")
            client.verifyCode(session.sessionId, "bob@example.org", "123456")
            assertTrue(client.isVerified(session.sessionId))

            assertEquals("/v1/sessions", server.takeRequest().url.encodedPath)
            assertEquals("/v1/sessions/abc/send-code", server.takeRequest().url.encodedPath)
            assertEquals("/v1/sessions/abc/verify-code", server.takeRequest().url.encodedPath)
            assertEquals("/v1/sessions/abc", server.takeRequest().url.encodedPath)
        }
    }

    @Test
    fun `mint sends only the public key and returns the token`() = runTest {
        MockWebServer().use { server ->
            server.start()
            // The client generates a fresh keypair per mint. To echo the key
            // back, run the request first, then serve a matching response —
            // MockWebServer3 supports response supplier via Dispatcher.
            server.dispatcher = object : mockwebserver3.Dispatcher() {
                override fun dispatch(request: mockwebserver3.RecordedRequest): MockResponse {
                    val body = JSONObject(request.body?.utf8() ?: "{}")
                    val holderPub = body.optString("holder_pub_b64")
                    assertTrue(holderPub.isNotEmpty())
                    // No seed field anywhere in the request.
                    assertTrue(!body.has("holder_seed_b64"))
                    val resp = JSONObject()
                        .put("token_family", "private_identity")
                        .put("token_b64", Wire.b64Encode(ByteArray(100) { 7 }))
                        .put("holder_alg", "ed25519")
                        .put("holder_pub_b64", holderPub)
                        .put("key_version", 1)
                    return MockResponse.Builder()
                        .code(200)
                        .body(resp.toString())
                        .build()
                }
            }
            val client = EnrollClient(server.url("/").toString())
            val token = client.mint("session-1")
            assertEquals(100, token.tokenBytes.size)
            assertEquals(32, token.holderSeed.size)
        }
    }

    @Test
    fun `errors surface the issuer message`() = runTest {
        MockWebServer().use { server ->
            server.enqueue(
                MockResponse.Builder()
                    .code(403)
                    .body("""{"error":"mint denied"}""")
                    .build(),
            )
            server.start()
            val client = EnrollClient(server.url("/").toString())
            try {
                client.mint("session-1")
                throw AssertionError("expected EnrollException")
            } catch (e: EnrollException) {
                assertTrue(e.message!!.contains("mint denied"))
            }
        }
    }

    private fun json(body: String): MockResponse =
        MockResponse.Builder().code(200).body(body).build()
}

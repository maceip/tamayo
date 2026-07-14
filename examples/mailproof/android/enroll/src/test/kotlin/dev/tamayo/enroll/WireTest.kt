package dev.tamayo.enroll

import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WireTest {

    /**
     * Golden vector generated from the Go side:
     * tokenprofile.PrivateIdentityPresentationMessage("https://imagehost.test",
     * nonce=00..1f, digest=ff..e0, issuedAt=1700000000).
     */
    @Test
    fun `presentation message matches Go tokenprofile vector`() {
        val nonce = ByteArray(32) { it.toByte() }
        val digest = ByteArray(32) { (0xff - it).toByte() }
        val message = Wire.presentationMessage("https://imagehost.test", nonce, digest, 1_700_000_000L)
        val expectedHex =
            "6561742d706173732f7076742d706f70000000001668747470733a2f2f696d616765686f73742e74657374" +
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0" +
                "000000006553f100"
        assertEquals(expectedHex, message.toHex())
    }

    @Test
    fun `ed25519 signature verifies with JDK verifier`() {
        val seed = ByteArray(32) { (it * 7).toByte() }
        val message = "presentation bytes".toByteArray()
        val signature = Wire.signEd25519(seed, message)
        val publicKey = Wire.ed25519PublicKey(seed)
        assertEquals(32, publicKey.size)
        assertEquals(64, signature.size)

        // Cross-check against the JDK's independent Ed25519 implementation:
        // wrap the raw public key in an X.509 SubjectPublicKeyInfo.
        val prefix = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        )
        val spki = prefix + publicKey
        val kf = java.security.KeyFactory.getInstance("Ed25519")
        val pub = kf.generatePublic(X509EncodedKeySpec(spki))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(pub)
        verifier.update(message)
        assertTrue(verifier.verify(signature))
    }

    @Test
    fun `minted token storage round-trips`() {
        val token = MintedToken(ByteArray(64) { it.toByte() }, ByteArray(32) { (it + 1).toByte() })
        val restored = MintedToken.fromStorageString(token.toStorageString())
        assertArrayEquals(token.tokenBytes, restored.tokenBytes)
        assertArrayEquals(token.holderSeed, restored.holderSeed)
    }

    @Test
    fun `presentation signature covers token digest`() {
        val token = MintedToken(ByteArray(64) { 3 }, ByteArray(32) { 5 })
        val nonce = ByteArray(32) { 9 }
        val signature = token.signPresentation("https://x.test", nonce, 1_700_000_000L)
        val expectedMessage = Wire.presentationMessage(
            "https://x.test",
            nonce,
            MessageDigest.getInstance("SHA-256").digest(token.tokenBytes),
            1_700_000_000L,
        )
        // Same inputs, same signature (Ed25519 is deterministic).
        assertArrayEquals(Wire.signEd25519(token.holderSeed, expectedMessage), signature)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}

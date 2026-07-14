package dev.tamayo.enroll

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.Base64
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec

/**
 * Wire-format helpers, byte-compatible with tamayo's Go `tokenprofile`
 * package. Everything here is deterministic and covered by a test vector
 * generated from the Go implementation.
 */
internal object Wire {
    private const val POP_DOMAIN = "eat-pass/pvt-pop\u0000"
    private const val DIGEST_BYTES = 32
    const val ED25519_SEED_BYTES = 32

    /** Mirrors tokenprofile.PrivateIdentityPresentationMessage. */
    fun presentationMessage(
        origin: String,
        nonce: ByteArray,
        tokenDigest: ByteArray,
        issuedAt: Long,
    ): ByteArray {
        require(nonce.size == DIGEST_BYTES) { "nonce must be $DIGEST_BYTES bytes" }
        require(tokenDigest.size == DIGEST_BYTES) { "token digest must be $DIGEST_BYTES bytes" }
        val originBytes = origin.toByteArray(Charsets.UTF_8)
        val buffer = ByteBuffer.allocate(
            POP_DOMAIN.length + Int.SIZE_BYTES + originBytes.size +
                DIGEST_BYTES + DIGEST_BYTES + Long.SIZE_BYTES,
        ).order(ByteOrder.BIG_ENDIAN)
        buffer.put(POP_DOMAIN.toByteArray(Charsets.ISO_8859_1))
        buffer.putInt(originBytes.size)
        buffer.put(originBytes)
        buffer.put(nonce)
        buffer.put(tokenDigest)
        buffer.putLong(issuedAt)
        return buffer.array()
    }

    fun ed25519PublicKey(seed: ByteArray): ByteArray {
        require(seed.size == ED25519_SEED_BYTES) { "ed25519 seed must be $ED25519_SEED_BYTES bytes" }
        val spec = EdDSANamedCurveTable.getByName("Ed25519") ?: error("Ed25519 curve missing")
        return EdDSAPrivateKey(EdDSAPrivateKeySpec(seed, spec)).abyte
    }

    fun signEd25519(seed: ByteArray, message: ByteArray): ByteArray {
        require(seed.size == ED25519_SEED_BYTES) { "ed25519 seed must be $ED25519_SEED_BYTES bytes" }
        val spec = EdDSANamedCurveTable.getByName("Ed25519") ?: error("Ed25519 curve missing")
        val engine = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        engine.initSign(EdDSAPrivateKey(EdDSAPrivateKeySpec(seed, spec)))
        engine.update(message)
        return engine.sign()
    }

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    fun b64Encode(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun b64Decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
}

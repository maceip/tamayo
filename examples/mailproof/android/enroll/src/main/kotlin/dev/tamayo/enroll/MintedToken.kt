package dev.tamayo.enroll

/**
 * A minted private-identity token plus the on-device holder seed.
 *
 * The token is reusable: each consumer hands out a single-use nonce, the
 * holder signs a presentation over it, and the consumer learns only an
 * origin-bound pseudonym. Persist both fields (e.g. in EncryptedSharedPreferences
 * or the Keystore-wrapped storage of your choice); the seed never goes over
 * the network.
 */
class MintedToken(
    val tokenBytes: ByteArray,
    val holderSeed: ByteArray,
) {
    val tokenB64: String get() = Wire.b64Encode(tokenBytes)

    /**
     * Signs one presentation of this token for [origin] over the consumer's
     * challenge [nonce]. Returns the signature to send alongside the token,
     * nonce, and [issuedAtEpochSeconds].
     */
    fun signPresentation(
        origin: String,
        nonce: ByteArray,
        issuedAtEpochSeconds: Long = System.currentTimeMillis() / 1000L,
    ): ByteArray {
        val message = Wire.presentationMessage(
            origin = origin,
            nonce = nonce,
            tokenDigest = Wire.sha256(tokenBytes),
            issuedAt = issuedAtEpochSeconds,
        )
        return Wire.signEd25519(holderSeed, message)
    }

    fun toStorageString(): String = Wire.b64Encode(tokenBytes) + "." + Wire.b64Encode(holderSeed)

    companion object {
        fun fromStorageString(value: String): MintedToken {
            val (token, seed) = value.split(".", limit = 2)
            return MintedToken(Wire.b64Decode(token), Wire.b64Decode(seed))
        }
    }
}

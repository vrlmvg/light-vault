package io.github.vrlmvg.vault

import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.encodings.OAEPEncoding
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.util.PrivateKeyFactory
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Bitwarden account KDF settings, from prelogin / the token response. */
data class KdfConfig(
    val type: Int,
    val iterations: Int,
    val memoryMiB: Int? = null,
    val parallelism: Int? = null,
) {
    /** Within the bounds Bitwarden's own clients accept. */
    fun isSafe(): Boolean = when (type) {
        PBKDF2 -> iterations in 5_000..2_000_000
        ARGON2ID -> iterations in 2..10 && (memoryMiB ?: 64) in 16..1024 && (parallelism ?: 4) in 1..16
        else -> false
    }

    companion object {
        const val PBKDF2 = 0
        const val ARGON2ID = 1
    }
}

/** AES-256-CBC key with optional HMAC-SHA256 key (Bitwarden's "SymmetricCryptoKey"). */
class SymmetricKey(val encKey: ByteArray, val macKey: ByteArray?) {
    fun wipe() {
        encKey.fill(0)
        macKey?.fill(0)
    }

    companion object {
        /** 64 bytes = enc ‖ mac; 32 bytes = legacy enc-only key. */
        fun fromBytes(bytes: ByteArray): SymmetricKey = when (bytes.size) {
            64 -> SymmetricKey(bytes.copyOfRange(0, 32), bytes.copyOfRange(32, 64))
            32 -> SymmetricKey(bytes.copyOf(), null)
            else -> throw VaultCryptoException("Unexpected key length ${bytes.size}")
        }
    }
}

class VaultCryptoException(message: String) : Exception(message)

object BitwardenCrypto {
    private val b64 = Base64.getDecoder()

    /** Master key from the master password; the salt is the account email, trimmed and lowercased. */
    fun masterKey(password: String, email: String, kdf: KdfConfig): ByteArray {
        val salt = email.trim().lowercase().toByteArray(Charsets.UTF_8)
        val secret = password.toByteArray(Charsets.UTF_8)
        return when (kdf.type) {
            KdfConfig.PBKDF2 -> pbkdf2(secret, salt, kdf.iterations)
            KdfConfig.ARGON2ID -> {
                val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(kdf.iterations)
                    .withMemoryAsKB((kdf.memoryMiB ?: 64) * 1024)
                    .withParallelism(kdf.parallelism ?: 4)
                    .withSalt(MessageDigest.getInstance("SHA-256").digest(salt))
                    .build()
                ByteArray(32).also { out ->
                    Argon2BytesGenerator().apply { init(params) }.generateBytes(secret, out)
                }
            }
            else -> throw VaultCryptoException("Unsupported KDF type ${kdf.type}")
        }
    }

    /** What the server checks at login: PBKDF2-SHA256(masterKey, password, 1). */
    fun masterPasswordHash(masterKey: ByteArray, password: String): String =
        Base64.getEncoder().encodeToString(pbkdf2(masterKey, password.toByteArray(Charsets.UTF_8), 1))

    /** HKDF-Expand the 32-byte master key into an enc ‖ mac key pair. */
    fun stretch(masterKey: ByteArray): SymmetricKey =
        SymmetricKey(hkdfExpand(masterKey, "enc"), hkdfExpand(masterKey, "mac"))

    /** Opens the account's protected user key ("Key" in the token response / profile.key). */
    fun decryptUserKey(protectedKey: String, masterKey: ByteArray): SymmetricKey {
        val enc = EncString.parse(protectedKey)
        val bytes = when (enc.type) {
            // Legacy accounts: encrypted directly with the (unstretched) master key, no MAC.
            0 -> enc.decryptWith(SymmetricKey(masterKey, null))
            2 -> enc.decryptWith(stretch(masterKey))
            else -> throw VaultCryptoException("Unsupported user key type ${enc.type}")
        }
        return SymmetricKey.fromBytes(bytes)
    }

    /** RSA-OAEP decryption of an organization key (EncString types 3, 4, 5, 6). */
    fun decryptWithPrivateKey(encString: String, pkcs8PrivateKey: ByteArray): ByteArray {
        val enc = EncString.parse(encString)
        val digest = when (enc.type) {
            3, 5 -> SHA256Digest()
            4, 6 -> SHA1Digest()
            else -> throw VaultCryptoException("Not an RSA EncString (type ${enc.type})")
        }
        val engine = OAEPEncoding(RSAEngine(), digest, digest, null)
        engine.init(false, PrivateKeyFactory.createKey(pkcs8PrivateKey))
        return engine.processBlock(enc.data, 0, enc.data.size)
    }

    internal fun pbkdf2(secret: ByteArray, salt: ByteArray, iterations: Int): ByteArray {
        val generator = PKCS5S2ParametersGenerator(SHA256Digest())
        generator.init(secret, salt, iterations)
        return (generator.generateDerivedParameters(256) as KeyParameter).key
    }

    private fun hkdfExpand(prk: ByteArray, info: String): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest())
        generator.init(HKDFParameters.skipExtractParameters(prk, info.toByteArray(Charsets.UTF_8)))
        return ByteArray(32).also { generator.generateBytes(it, 0, 32) }
    }
}

/**
 * Bitwarden's encrypted value format: "<type>.<iv>|<data>|<mac>" (symmetric) or
 * "<type>.<data>[|<mac>]" (RSA). Fields are base64.
 */
class EncString private constructor(val type: Int, val iv: ByteArray?, val data: ByteArray, val mac: ByteArray?) {

    fun decryptWith(key: SymmetricKey): ByteArray {
        val iv = iv ?: throw VaultCryptoException("Missing IV")
        when (type) {
            // Unauthenticated; only valid for legacy keys that have no MAC part. Otherwise a server could
            // swap in a value it can tamper with.
            0 -> if (key.macKey != null) throw VaultCryptoException("Unauthenticated value for a MAC key")
            2 -> {
                val macKey = key.macKey ?: throw VaultCryptoException("Key has no MAC part")
                val expected = Mac.getInstance("HmacSHA256").run {
                    init(SecretKeySpec(macKey, "HmacSHA256"))
                    update(iv)
                    doFinal(data)
                }
                if (mac == null || !MessageDigest.isEqual(expected, mac)) throw VaultCryptoException("MAC mismatch")
            }
            else -> throw VaultCryptoException("Unsupported symmetric EncString type $type")
        }
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key.encKey, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    fun decryptString(key: SymmetricKey): String = decryptWith(key).toString(Charsets.UTF_8)

    companion object {
        fun parse(value: String): EncString {
            val dot = value.indexOf('.')
            if (dot < 1) throw VaultCryptoException("Malformed EncString")
            val type = value.substring(0, dot).toIntOrNull() ?: throw VaultCryptoException("Malformed EncString")
            val parts = value.substring(dot + 1).split('|')
            val d = Base64.getDecoder()
            val enc = try {
                when (type) {
                    0 -> EncString(type, d.decode(parts[0]), d.decode(parts[1]), null)
                    1, 2 -> EncString(type, d.decode(parts[0]), d.decode(parts[1]), d.decode(parts.getOrNull(2) ?: ""))
                    3, 4 -> EncString(type, null, d.decode(parts[0]), null)
                    5, 6 -> EncString(type, null, d.decode(parts[0]), parts.getOrNull(1)?.let(d::decode))
                    else -> throw VaultCryptoException("Unsupported EncString type $type")
                }
            } catch (e: IndexOutOfBoundsException) {
                throw VaultCryptoException("Malformed EncString")
            } catch (e: IllegalArgumentException) {
                throw VaultCryptoException("Malformed EncString")
            }
            if (enc.iv != null && enc.iv.size != 16) throw VaultCryptoException("Malformed EncString")
            return enc
        }
    }
}

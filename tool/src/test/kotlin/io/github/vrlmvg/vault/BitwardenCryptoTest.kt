package io.github.vrlmvg.vault

import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Expected values come from the test suite of Bitwarden's own SDK (bitwarden/sdk-internal, bitwarden-crypto). */
class BitwardenCryptoTest {
    private val b64 = Base64.getDecoder()

    @Test
    fun pbkdf2MasterPasswordHashNormalisesEmail() {
        val kdf = KdfConfig(KdfConfig.PBKDF2, 100_000)
        for (email in listOf("test@bitwarden.com", "TEST@bitwarden.com", " test@bitwarden.com")) {
            val key = BitwardenCrypto.masterKey("asdfasdf", email, kdf)
            assertEquals("wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=", BitwardenCrypto.masterPasswordHash(key, "asdfasdf"))
        }
    }

    @Test
    fun argon2idMasterPasswordHash() {
        val kdf = KdfConfig(KdfConfig.ARGON2ID, iterations = 4, memoryMiB = 32, parallelism = 2)
        val key = BitwardenCrypto.masterKey("asdfasdf", "test_salt", kdf)
        assertEquals("PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ=", BitwardenCrypto.masterPasswordHash(key, "asdfasdf"))
    }

    @Test
    fun decryptsLegacyType0UserKey() {
        val masterKey = BitwardenCrypto.masterKey("asdfasdfasdf", "legacy@bitwarden.com", KdfConfig(KdfConfig.PBKDF2, 600_000))
        val userKey = BitwardenCrypto.decryptUserKey(
            "0.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI=",
            masterKey,
        )
        assertContentEquals(
            bytes(12, 95, 151, 203, 37, 4, 236, 67, 137, 97, 90, 58, 6, 127, 242, 28, 209, 168, 125, 29, 118, 24, 213, 44, 117, 202, 2, 115, 132, 165, 125, 148),
            userKey.encKey,
        )
        assertContentEquals(
            bytes(186, 215, 234, 137, 24, 169, 227, 29, 218, 57, 180, 237, 73, 91, 189, 51, 253, 26, 17, 52, 226, 4, 134, 75, 194, 208, 178, 133, 128, 224, 140, 167),
            userKey.macKey,
        )
    }

    @Test
    fun decryptsType2Values() {
        val key = SymmetricKey.fromBytes(b64.decode("sJnO8rVi0dTwND43n0T9x7665s8mVUYNAaJ4nm7gx1iia1I7947URL60nwfIHaf9QJePO4VkNN0oT9jh4iC6aA=="))
        assertEquals(
            "Hello, World!",
            EncString.parse("2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=").decryptString(key),
        )
        assertContentEquals(
            bytes(1, 2, 3, 4, 5),
            EncString.parse("2.kTtIypq9OLzd5iMMbU11pQ==|J4i3hTtGVdg7EZ+AQv/ujg==|QJpSpotQVpIW8j8dR/8l015WJzAIxBaOmrz4Uj/V1JA=").decryptWith(key),
        )
    }

    @Test
    fun rejectsTamperedType2() {
        val key = SymmetricKey.fromBytes(b64.decode("sJnO8rVi0dTwND43n0T9x7665s8mVUYNAaJ4nm7gx1iia1I7947URL60nwfIHaf9QJePO4VkNN0oT9jh4iC6aA=="))
        assertFailsWith<VaultCryptoException> {
            EncString.parse("2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|AWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=").decryptString(key)
        }
    }

    @Test
    fun decryptsRsaOrganisationKeys() {
        // SymmetricCryptoKey::generate_seeded_for_unit_tests("test") = first 64 bytes of ChaCha20(SHA-256("test")).
        val expected = ByteArray(64).also { out ->
            ChaCha7539Engine().apply {
                init(true, ParametersWithIV(KeyParameter(MessageDigest.getInstance("SHA-256").digest("test".toByteArray())), ByteArray(12)))
            }.processBytes(ByteArray(64), 0, 64, out, 0)
        }
        for (value in listOf(RSA_SHA256, RSA_SHA1, RSA_SHA1 .replaceFirst("4.", "6.") + "|AA==")) {
            assertContentEquals(expected, BitwardenCrypto.decryptWithPrivateKey(value, PRIVATE_KEY_DER), value.take(2))
        }
    }


    @Test
    fun rejectsUnauthenticatedValueForMacKey() {
        val key = SymmetricKey.fromBytes(b64.decode("sJnO8rVi0dTwND43n0T9x7665s8mVUYNAaJ4nm7gx1iia1I7947URL60nwfIHaf9QJePO4VkNN0oT9jh4iC6aA=="))
        val iv = ByteArray(16) { it.toByte() }
        val data = Cipher.getInstance("AES/CBC/PKCS5Padding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.encKey, "AES"), IvParameterSpec(iv))
            doFinal("swapped".toByteArray())
        }
        val type0 = EncString.parse("0.${Base64.getEncoder().encodeToString(iv)}|${Base64.getEncoder().encodeToString(data)}")
        assertFailsWith<VaultCryptoException> { type0.decryptWith(key) }
        // Legacy keys without a MAC part still open type 0 values.
        assertEquals("swapped", type0.decryptString(SymmetricKey(key.encKey.copyOf(), null)))
    }

    @Test
    fun malformedEncStringsFailCleanly() {
        for (value in listOf("2.", "2.AAAA", "2.!!!|AAAA|AAAA", "2.AAAA|AAAA|AAAA", "x.AAAA", "9.AAAA|AAAA")) {
            assertFailsWith<VaultCryptoException>(value) { EncString.parse(value) }
        }
    }

    @Test
    fun kdfSafetyBounds() {
        assertTrue(KdfConfig(KdfConfig.PBKDF2, 600_000).isSafe())
        assertTrue(KdfConfig(KdfConfig.ARGON2ID, 3, 64, 4).isSafe())
        assertTrue(KdfConfig(KdfConfig.ARGON2ID, 3).isSafe())
        assertFalse(KdfConfig(KdfConfig.PBKDF2, 1).isSafe())
        assertFalse(KdfConfig(KdfConfig.PBKDF2, 100_000_000).isSafe())
        assertFalse(KdfConfig(KdfConfig.ARGON2ID, 1, 64, 4).isSafe())
        assertFalse(KdfConfig(KdfConfig.ARGON2ID, 3, 8, 4).isSafe())
        assertFalse(KdfConfig(KdfConfig.ARGON2ID, 3, 4096, 4).isSafe())
        assertFalse(KdfConfig(7, 600_000).isSafe())
    }

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    private companion object {
        val PRIVATE_KEY_DER: ByteArray = Base64.getMimeDecoder().decode(
            """
            MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXRVrCX+2hfOQS
            8HzYUS2oc/jGVTZpv+/Ryuoh9d8ihYX9dd0cYh2tl6KWdFc88lPUH11Oxqy20Rk2
            e5r/RF6T9yM0Me3NPnaKt+hlhLtfoc0h86LnhD56A9FDUfuI0dVnPcrwNv0YJIo9
            4LwxtbqBULNvXl6wJ7WAbODrCQy5ZgMVg+iH+gGpwiqsZqHt+KuoHWcN53MSPDfa
            F4/YMB99U3TziJMOOJask1TEEnakMPln11PczNDazT17DXIxYrbPfutPdh6sLs6A
            QOajdZijfEvepgnOe7cQ7aeatiOJFrjTApKPGxOVRzEMX4XS4xbyhH0QxQeB6l16
            l8C0uxIBAgMBAAECggEASaWfeVDA3cVzOPFSpvJm20OTE+R6uGOU+7vh36TX/POq
            92qBuwbd0h0oMD32FxsXywd2IxtBDUSiFM9699qufTVuM0Q3tZw6lHDTOVG08+tP
            dr8qSbMtw7PGFxN79fHLBxejjO4IrM9lapjWpxEF+11x7r+wM+0xRZQ8sNFYG46a
            PfIaty4BGbL0I2DQ2y8I57iBCAy69eht59NLMm27fRWGJIWCuBIjlpfzET1j2HLX
            UIh5bTBNzqaN039WH49HczGE3mQKVEJZc/efk3HaVd0a1Sjzyn0QY+N1jtZN3jTR
            buDWA1AknkX1LX/0tUhuS3/7C3ejHxjw4Dk1ZLo5/QKBgQDIWvqFn0+IKRSu6Ua2
            hDsufIHHUNLelbfLUMmFthxabcUn4zlvIscJO00Tq/ezopSRRvbGiqnxjv/mYxuc
            vOUBeZtlus0Q9RTACBtw9TGoNTmQbEunJ2FOSlqbQxkBBAjgGEppRPt30iGj/VjA
            hCATq2MYOa/X4dVR51BqQAFIEwKBgQDBSIfTFKC/hDk6FKZlgwvupWYJyU9Rkyfs
            tPErZFmzoKhPkQ3YORo2oeAYmVUbS9I2iIYpYpYQJHX8jMuCbCz4ONxTCuSIXYQY
            UcUq4PglCKp31xBAE6TN8SvhfME9/MvuDssnQinAHuF0GDAhF646T3LLS1not6Vs
            zv7brwSoGwKBgQC88v/8cGfi80ssQZeMnVvq1UTXIeQcQnoY5lGHJl3K8mbS3TnX
            E6c9j417Fdz+rj8KWzBzwWXQB5pSPflWcdZO886Xu/mVGmy9RWgLuVFhXwCwsVEP
            jNX5ramRb0/vY0yzenUCninBsIxFSbIfrPtLUYCc4hpxr+sr2Mg/y6jpvQKBgBez
            MRRs3xkcuXepuI2R+BCXL1/b02IJTUf1F+1eLLGd7YV0H+J3fgNc7gGWK51hOrF9
            JBZHBGeOUPlaukmPwiPdtQZpu4QNE3l37VlIpKTF30E6mb+BqR+nht3rUjarnMXg
            AoEZ18y6/KIjpSMpqC92Nnk/EBM9EYe6Cf4eA9ApAoGAeqEUg46UTlJySkBKURGp
            Is3v1kkf5I0X8DnOhwb+HPxNaiEdmO7ckm8+tPVgppLcG0+tMdLjigFQiDUQk2y3
            WjyxP5ZvXu7U96jaJRI8PFMoE06WeVYcdIzrID2HvqH+w0UQJFrLJ/0Mn4stFAEz
            XKZBokBGnjFnTnKcs7nv/O8=
            """.trimIndent(),
        )
        const val RSA_SHA256 = "3.SUx5gWrgmAKs/S1BoQrqOmx2Hl5fPVBVHokW17Flvm4TpBnJJRkfoitp7Jc4dfazPYjWGlckJz6X+qe+/AWilS1mxtzS0PmDy7tS5xP0GRlB39dstCd5jDw1wPmTbXiLcQ5VTvzpRAfRMEYVveTsEvVTByvEYAGSn4TnCsUDykyhRbD0YcJ4r1KHLs1b3BCBy2M1Gl5nmwckH08CAXaf8VfuBFStAGRKueovqp4euneQla+4G4fXdVvb8qKPnu0iVuALIE6nUNmeOiA3xN3d+akMxbbGxrQ1Ca4TYWjHVdj9C6abngQHkjKNYQwGUXrYo160hP4LIHn/huK6bZe5dQ=="
        const val RSA_SHA1 = "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww=="
    }
}

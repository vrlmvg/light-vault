package io.github.vrlmvg.vault

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import java.io.File
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class WrongPinException(val attemptsLeft: Int) : Exception(
    if (attemptsLeft == 1) "Wrong PIN. 1 attempt left." else "Wrong PIN. $attemptsLeft attempts left.",
)
class PinWipedException : Exception("Too many wrong PINs. Sign in again with your master password.")

/**
 * Everything the vault keeps on the phone:
 * - the refresh token and the last sync response, encrypted with the Android Keystore key;
 * - the user key, encrypted with a PIN-derived key *and* the Keystore key.
 * The sync response itself is still Bitwarden-encrypted; nothing readable is stored.
 */
class VaultStore internal constructor(
    private val dataStore: DataStore<Preferences>,
    private val keystore: TotpSecretCipher,
    filesDir: File,
) {
    private val syncFile = File(filesDir, "vault.sync")

    val server: Flow<String?> = dataStore.data.map { it[SERVER] }
    val email: Flow<String?> = dataStore.data.map { it[EMAIL] }
    val lastSync: Flow<Long?> = dataStore.data.map { it[LAST_SYNC] }
    val hasPin: Flow<Boolean> = dataStore.data.map { it[WRAPPED_USER_KEY] != null }

    suspend fun deviceId(): String {
        dataStore.data.first()[DEVICE_ID]?.let { return it }
        val id = UUID.randomUUID().toString()
        dataStore.edit { it[DEVICE_ID] = id }
        return id
    }

    suspend fun saveAccount(server: String, email: String, refreshToken: String) {
        dataStore.edit {
            it[SERVER] = server
            it[EMAIL] = email
            it[REFRESH_TOKEN] = keystore.encrypt(refreshToken).toBase64()
        }
    }

    suspend fun refreshToken(): String? =
        dataStore.data.first()[REFRESH_TOKEN]?.let { runCatching { keystore.decrypt(it.fromBase64()) }.getOrNull() }

    suspend fun updateRefreshToken(token: String) {
        dataStore.edit { it[REFRESH_TOKEN] = keystore.encrypt(token).toBase64() }
    }

    suspend fun saveSync(json: String) = withContext(Dispatchers.IO) {
        syncFile.writeBytes(keystore.encrypt(json))
        dataStore.edit { it[LAST_SYNC] = System.currentTimeMillis() }
    }

    suspend fun loadSync(): String? = withContext(Dispatchers.IO) {
        if (!syncFile.exists()) null else runCatching { keystore.decrypt(syncFile.readBytes()) }.getOrNull()
    }

    /** Protects [userKey] with [pin] (PBKDF2 → AES-GCM) and then the Keystore key. */
    suspend fun setPin(pin: String, userKey: SymmetricKey) = withContext(Dispatchers.Default) {
        val salt = ByteArray(16).also(random::nextBytes)
        val pinKey = BitwardenCrypto.pbkdf2(pin.toByteArray(), salt, PIN_ITERATIONS)
        val iv = ByteArray(12).also(random::nextBytes)
        val sealed = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(pinKey, "AES"), GCMParameterSpec(128, iv))
            doFinal(userKey.encKey + (userKey.macKey ?: ByteArray(0)))
        }
        pinKey.fill(0)
        val wrapped = keystore.encrypt((salt + iv + sealed).toBase64())
        dataStore.edit {
            it[WRAPPED_USER_KEY] = wrapped.toBase64()
            it[PIN_FAILURES] = 0
        }
    }

    suspend fun unlockWithPin(pin: String): SymmetricKey = withContext(Dispatchers.Default) {
        val prefs = dataStore.data.first()
        val wrapped = prefs[WRAPPED_USER_KEY] ?: throw PinWipedException()
        val blob = keystore.decrypt(wrapped.fromBase64()).fromBase64()
        val salt = blob.copyOfRange(0, 16)
        val iv = blob.copyOfRange(16, 28)
        val pinKey = BitwardenCrypto.pbkdf2(pin.toByteArray(), salt, PIN_ITERATIONS)
        try {
            val key = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(pinKey, "AES"), GCMParameterSpec(128, iv))
                doFinal(blob, 28, blob.size - 28)
            }
            dataStore.edit { it[PIN_FAILURES] = 0 }
            SymmetricKey.fromBytes(key)
        } catch (e: AEADBadTagException) {
            val failures = (prefs[PIN_FAILURES] ?: 0) + 1
            if (failures >= MAX_PIN_ATTEMPTS) {
                dataStore.edit { it.remove(WRAPPED_USER_KEY); it.remove(PIN_FAILURES) }
                throw PinWipedException()
            }
            dataStore.edit { it[PIN_FAILURES] = failures }
            throw WrongPinException(MAX_PIN_ATTEMPTS - failures)
        } finally {
            pinKey.fill(0)
        }
    }

    /** Signs out: removes tokens, keys and the cached vault (the device id is kept). */
    suspend fun clear() = withContext(Dispatchers.IO) {
        syncFile.delete()
        dataStore.edit {
            it.remove(SERVER); it.remove(EMAIL); it.remove(REFRESH_TOKEN)
            it.remove(WRAPPED_USER_KEY); it.remove(PIN_FAILURES); it.remove(LAST_SYNC)
        }
    }

    private fun ByteArray.toBase64() = Base64.getEncoder().encodeToString(this)
    private fun String.fromBase64() = Base64.getDecoder().decode(this)

    private companion object {
        val random = SecureRandom()
        const val PIN_ITERATIONS = 210_000
        const val MAX_PIN_ATTEMPTS = 5
        val SERVER = stringPreferencesKey("server")
        val EMAIL = stringPreferencesKey("email")
        val DEVICE_ID = stringPreferencesKey("device_id")
        val REFRESH_TOKEN = stringPreferencesKey("refresh_token")
        val WRAPPED_USER_KEY = stringPreferencesKey("wrapped_user_key")
        val PIN_FAILURES = intPreferencesKey("pin_failures")
        val LAST_SYNC = longPreferencesKey("last_sync")
    }
}

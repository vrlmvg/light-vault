package io.github.vrlmvg.vault

import com.thelightphone.sdk.SealedLightContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Process-wide vault state. Decrypted data only ever lives here, in memory, while unlocked. */
object VaultSession {
    sealed interface State {
        data object Locked : State
        data class Unlocked(val vault: DecryptedVault) : State
    }

    private val _state = MutableStateFlow<State>(State.Locked)
    val state: StateFlow<State> = _state.asStateFlow()

    @Volatile private var userKey: SymmetricKey? = null
    @Volatile private var pausedAtMillis: Long? = null
    @Volatile private var store: VaultStore? = null
    private val syncMutex = Mutex()

    fun store(context: SealedLightContext): VaultStore = store ?: synchronized(this) {
        store ?: VaultStore(context.dataStore, TotpSecretCipher(), context.filesDir).also { store = it }
    }

    val isUnlocked: Boolean get() = userKey != null

    /** Opens the cached vault with [key]; the vault may be empty until the first sync. */
    suspend fun unlock(store: VaultStore, key: SymmetricKey) {
        userKey = key
        pausedAtMillis = null
        val cached = store.loadSync()
        _state.value = State.Unlocked(
            withContext(Dispatchers.Default) { cached?.let { VaultDecryptor.decrypt(it, key) } ?: DecryptedVault(emptyList(), 0) },
        )
    }

    fun lock() {
        userKey?.wipe()
        userKey = null
        _state.value = State.Locked
    }

    /** Called when the tool goes to the background; locks if it stays away too long. */
    fun onPaused() {
        pausedAtMillis = System.currentTimeMillis()
    }

    fun lockIfIdle() {
        val paused = pausedAtMillis ?: return
        if (System.currentTimeMillis() - paused > AUTO_LOCK_MILLIS) lock()
        pausedAtMillis = null
    }

    /** Fetches the latest vault from the server using the stored refresh token. */
    suspend fun sync(store: VaultStore, accessToken: String? = null): DecryptedVault? = syncMutex.withLock {
        val server = store.server.first() ?: throw VaultSessionExpiredException()
        val api = VaultApi(server)
        try {
            val token = accessToken ?: run {
                val refresh = store.refreshToken() ?: throw VaultSessionExpiredException()
                val response = api.refresh(refresh)
                response.refreshToken?.let { if (it != refresh) store.updateRefreshToken(it) }
                response.accessToken
            }
            val json = api.sync(token)
            store.saveSync(json)
            val key = userKey ?: return@withLock null
            val vault = withContext(Dispatchers.Default) { VaultDecryptor.decrypt(json, key) }
            _state.value = State.Unlocked(vault)
            vault
        } finally {
            api.close()
        }
    }

    private const val AUTO_LOCK_MILLIS = 60_000L
}

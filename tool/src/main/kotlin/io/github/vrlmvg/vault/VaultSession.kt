package io.github.vrlmvg.vault

import android.os.SystemClock
import com.thelightphone.sdk.SealedLightContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
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
    private val timerScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var autoLockJob: Job? = null

    fun store(context: SealedLightContext): VaultStore = store ?: synchronized(this) {
        store ?: VaultStore(context.dataStore, TotpSecretCipher(), context.filesDir).also { store = it }
    }

    val isUnlocked: Boolean get() = userKey != null

    /** Opens the cached vault with [key]; the vault may be empty until the first sync. */
    suspend fun unlock(store: VaultStore, key: SymmetricKey) {
        userKey = key
        pausedAtMillis = null
        val cached = store.loadSync()
        // A cache this key can't open (another account, a rotated key) shows as empty until the next sync
        // replaces it, instead of making every sign-in fail.
        val vault = withContext(Dispatchers.Default) {
            cached?.let { runCatching { VaultDecryptor.decrypt(it, key) }.getOrNull() } ?: DecryptedVault(emptyList(), 0)
        }
        // Locked (or re-unlocked) while decrypting: don't put the vault back on screen.
        if (userKey === key) _state.value = State.Unlocked(vault)
    }

    fun lock() {
        autoLockJob?.cancel()
        autoLockJob = null
        pausedAtMillis = null
        userKey?.wipe()
        userKey = null
        _state.value = State.Locked
    }

    /**
     * Called by every screen when the tool goes to the background. Locks after [AUTO_LOCK_MILLIS];
     * the timer may not run while Android freezes the app, so [lockIfIdle] checks again on return.
     */
    fun onPaused() {
        if (userKey == null) return
        pausedAtMillis = SystemClock.elapsedRealtime()
        autoLockJob?.cancel()
        autoLockJob = timerScope.launch {
            delay(AUTO_LOCK_MILLIS)
            lock()
        }
    }

    /** Called by every screen when it is shown again. */
    fun lockIfIdle() {
        autoLockJob?.cancel()
        autoLockJob = null
        val paused = pausedAtMillis ?: return
        pausedAtMillis = null
        if (SystemClock.elapsedRealtime() - paused >= AUTO_LOCK_MILLIS) lock()
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
            if (userKey !== key) return@withLock null
            _state.value = State.Unlocked(vault)
            vault
        } finally {
            api.close()
        }
    }

    private const val AUTO_LOCK_MILLIS = 60_000L
}

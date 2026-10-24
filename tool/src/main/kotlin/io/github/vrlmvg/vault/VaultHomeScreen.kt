package io.github.vrlmvg.vault

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewModelScope
import com.thelightphone.sdk.InitialScreen
import com.thelightphone.sdk.LightScreen
import com.thelightphone.sdk.LightViewModel
import com.thelightphone.sdk.SealedLightActivity
import com.thelightphone.sdk.SimpleLightScreen
import com.thelightphone.sdk.rememberKeyboardOptions
import com.thelightphone.sdk.ui.LightBarButton
import com.thelightphone.sdk.ui.LightBottomBar
import com.thelightphone.sdk.ui.LightFullscreenModal
import com.thelightphone.sdk.ui.LightIcons
import com.thelightphone.sdk.ui.LightScrollView
import com.thelightphone.sdk.ui.LightTextInputEditor
import com.thelightphone.sdk.ui.gridUnitsAsDp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

sealed interface HomeMode {
    data object Loading : HomeMode
    data object SignedOut : HomeMode
    data object PinWiped : HomeMode
    data object Locked : HomeMode
    data object Unlocking : HomeMode
    data class Vault(val vault: DecryptedVault) : HomeMode
}

class VaultHomeViewModel(private val store: VaultStore) : LightViewModel<Unit>() {
    private val unlocking = MutableStateFlow(false)
    val query = MutableStateFlow("")
    val searching = MutableStateFlow(false)
    val message = MutableStateFlow<String?>(null)
    val pinSession = MutableStateFlow(0)

    val mode: StateFlow<HomeMode> = combine(store.email, store.hasPin, VaultSession.state, unlocking) { email, hasPin, session, busy ->
        when {
            email == null -> HomeMode.SignedOut
            session is VaultSession.State.Unlocked -> HomeMode.Vault(session.vault)
            busy -> HomeMode.Unlocking
            !hasPin -> HomeMode.PinWiped
            else -> HomeMode.Locked
        }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, HomeMode.Loading)

    override fun onScreenShow(screen: SimpleLightScreen<Unit>) {
        super.onScreenShow(screen)
        VaultSession.lockIfIdle()
        if (VaultSession.isUnlocked) syncIfDue()
        // The vault may have locked while the tool was in the background; a PIN editor created
        // then doesn't take input, so start a fresh one now that the screen is showing.
        else pinSession.value++
    }

    override fun onAppPause() {
        super.onAppPause()
        VaultSession.onPaused()
    }

    fun unlock(pin: CharSequence) {
        if (pin.isEmpty()) return
        unlocking.value = true
        viewModelScope.launch {
            runCatching { VaultSession.unlock(store, store.unlockWithPin(pin.toString())) }
                .onSuccess { syncIfDue() }
                .onFailure { message.value = describeError(it); pinSession.value++ }
            unlocking.value = false
        }
    }

    fun startSearch() { searching.value = true }

    fun search(text: CharSequence) {
        query.value = text.toString().trim()
        searching.value = false
    }

    fun cancelSearch() { searching.value = false }

    fun clearQuery() { query.value = "" }

    fun dismissMessage() { message.value = null }

    override fun onBackPressed(): Boolean = when {
        searching.value -> { searching.value = false; true }
        query.value.isNotEmpty() -> { query.value = ""; true }
        else -> false
    }

    private fun syncIfDue() {
        viewModelScope.launch {
            val last = store.lastSync.first() ?: 0
            if (System.currentTimeMillis() - last < AUTO_SYNC_MILLIS) return@launch
            runCatching { VaultSession.sync(store) }
                .onFailure { if (it is VaultSessionExpiredException) message.value = describeError(it) }
        }
    }

    private companion object {
        const val AUTO_SYNC_MILLIS = 5 * 60_000L
    }
}

@InitialScreen
class VaultHomeScreen(sealedActivity: SealedLightActivity) : LightScreen<Unit, VaultHomeViewModel>(sealedActivity) {
    private val store by lazy { VaultSession.store(lightContext) }

    override val viewModelClass: Class<VaultHomeViewModel>
        get() = VaultHomeViewModel::class.java

    override fun createViewModel() = VaultHomeViewModel(store)

    private fun openSignIn() = navigateTo(screenFactory = { SignInScreen(it) })
    private fun openSettings() = navigateTo(screenFactory = { VaultSettingsScreen(it) })
    private fun openItem(item: VaultItem) = navigateTo(screenFactory = { ItemScreen(it, item.id) })

    @Composable
    override fun Content() {
        val mode by viewModel.mode.collectAsState()
        val query by viewModel.query.collectAsState()
        val searching by viewModel.searching.collectAsState()
        val message by viewModel.message.collectAsState()
        val pinSession by viewModel.pinSession.collectAsState()
        val field = rememberTextFieldState("")
        val keyboardOptionsFlow = rememberKeyboardOptions()
        LaunchedEffect(pinSession, searching) { field.clearText() }

        VaultTheme {
            when {
                mode == HomeMode.Locked -> LightTextInputEditor(
                    title = "Enter PIN",
                    state = field,
                    keyboardOptionsFlow = keyboardOptionsFlow,
                    onSubmit = viewModel::unlock,
                    onBack = { goBack() },
                    submitLabel = "UNLOCK",
                    singleLine = true,
                    showBackButton = false,
                    editorKey = pinSession,
                    modifier = Modifier.fillMaxSize(),
                )
                searching -> LightTextInputEditor(
                    title = "Search",
                    state = field,
                    keyboardOptionsFlow = keyboardOptionsFlow,
                    onSubmit = viewModel::search,
                    onBack = viewModel::cancelSearch,
                    submitIcon = LightIcons.SEARCH,
                    singleLine = true,
                    modifier = Modifier.fillMaxSize(),
                )
                else -> Column(modifier = Modifier.fillMaxSize()) {
                    when (val m = mode) {
                        HomeMode.Loading, HomeMode.Locked -> Unit
                        HomeMode.SignedOut -> {
                            TopBar("Vaultwarden", onBack = null)
                            CenteredMessage("Sign in to your Vaultwarden or Bitwarden account to look up your passwords.", "SIGN IN", ::openSignIn)
                        }
                        HomeMode.PinWiped -> {
                            TopBar("Vaultwarden", onBack = null)
                            CenteredMessage("Your PIN was entered wrong too many times. Sign in again with your master password.", "SIGN IN", ::openSignIn)
                        }
                        HomeMode.Unlocking -> {
                            TopBar("Vaultwarden", onBack = null)
                            Working("Unlocking…")
                        }
                        is HomeMode.Vault -> VaultList(m.vault, query)
                    }
                }
            }
            message?.let { LightFullscreenModal(message = it, onClose = viewModel::dismissMessage) }
        }
    }

    @Composable
    private fun androidx.compose.foundation.layout.ColumnScope.VaultList(vault: DecryptedVault, query: String) {
        val items = if (query.isEmpty()) vault.items else vault.items.filter { it.matches(query) }
        TopBar(
            title = if (query.isEmpty()) "Vaultwarden" else "“$query”",
            onBack = if (query.isEmpty()) null else viewModel::clearQuery,
        )
        if (items.isEmpty()) {
            CenteredMessage(if (query.isEmpty()) "Your vault is empty, or still syncing." else "Nothing matches “$query”.")
        } else {
            LightScrollView(modifier = Modifier.weight(1f).fillMaxWidth().padding(start = 1f.gridUnitsAsDp())) {
                items.forEach { item ->
                    ListRow(item.name, item.subtitle ?: item.type.label) { openItem(item) }
                }
            }
        }
        LightBottomBar(
            listOf(
                LightBarButton.LightIcon(LightIcons.SETTINGS, onClick = ::openSettings, contentDescription = "Settings"),
                LightBarButton.LightIcon(LightIcons.SEARCH, onClick = viewModel::startSearch, contentDescription = "Search"),
            ),
        )
    }
}

private fun VaultItem.matches(query: String): Boolean =
    name.contains(query, ignoreCase = true) ||
        subtitle?.contains(query, ignoreCase = true) == true ||
        fields.any { it.kind == FieldKind.Url && it.value.contains(query, ignoreCase = true) }

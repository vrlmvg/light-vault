package io.github.vrlmvg.vault

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.lifecycle.viewModelScope
import com.thelightphone.sdk.LightScreen
import com.thelightphone.sdk.LightViewModel
import com.thelightphone.sdk.SealedLightActivity
import com.thelightphone.sdk.SimpleLightScreen
import com.thelightphone.sdk.ui.LightBarButton
import com.thelightphone.sdk.ui.LightBottomBar
import com.thelightphone.sdk.ui.LightFullscreenModal
import com.thelightphone.sdk.ui.LightIcons
import com.thelightphone.sdk.ui.LightText
import com.thelightphone.sdk.ui.LightTextVariant
import com.thelightphone.sdk.ui.gridUnitsAsDp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class VaultSettingsViewModel(private val store: VaultStore) : LightViewModel<Unit>() {
    val email = store.email.stateIn(viewModelScope, SharingStarted.Eagerly, null)
    val server = store.server.stateIn(viewModelScope, SharingStarted.Eagerly, null)
    val lastSync = store.lastSync.stateIn(viewModelScope, SharingStarted.Eagerly, null)
    val syncing = MutableStateFlow(false)
    val confirmingSignOut = MutableStateFlow(false)
    val message = MutableStateFlow<String?>(null)
    val closed = MutableStateFlow(false)

    fun syncNow() {
        syncing.value = true
        viewModelScope.launch {
            runCatching { VaultSession.sync(store) }
                .onSuccess { vault ->
                    message.value = vault?.let {
                        "Vault synced. ${it.items.size} items" + if (it.failed > 0) ", ${it.failed} couldn't be decrypted." else "."
                    } ?: "Vault synced."
                }
                .onFailure { message.value = describeError(it) }
            syncing.value = false
        }
    }

    fun lockNow() {
        VaultSession.lock()
        closed.value = true
    }

    fun signOut() {
        viewModelScope.launch {
            VaultSession.lock()
            store.clear()
            // Reset first: goBack() asks onBackPressed(), which would otherwise just close the prompt.
            confirmingSignOut.value = false
            closed.value = true
        }
    }

    fun dismissMessage() { message.value = null }

    override fun onScreenShow(screen: SimpleLightScreen<Unit>) {
        super.onScreenShow(screen)
        VaultSession.lockIfIdle()
    }

    override fun onAppPause() {
        super.onAppPause()
        VaultSession.onPaused()
    }

    override fun onBackPressed(): Boolean {
        if (confirmingSignOut.value) { confirmingSignOut.value = false; return true }
        return false
    }
}

class VaultSettingsScreen(sealedActivity: SealedLightActivity) : LightScreen<Unit, VaultSettingsViewModel>(sealedActivity) {
    override val viewModelClass: Class<VaultSettingsViewModel>
        get() = VaultSettingsViewModel::class.java

    override fun createViewModel() = VaultSettingsViewModel(VaultSession.store(lightContext))

    @Composable
    override fun Content() {
        val email by viewModel.email.collectAsState()
        val server by viewModel.server.collectAsState()
        val lastSync by viewModel.lastSync.collectAsState()
        val syncing by viewModel.syncing.collectAsState()
        val confirming by viewModel.confirmingSignOut.collectAsState()
        val message by viewModel.message.collectAsState()
        val closed by viewModel.closed.collectAsState()
        LaunchedEffect(closed) { if (closed) goBack() }

        VaultTheme {
            Column(modifier = Modifier.fillMaxSize()) {
                TopBar("Settings", onBack = { goBack() })
                if (confirming) {
                    Box(
                        modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = 1f.gridUnitsAsDp()),
                        contentAlignment = Alignment.Center,
                    ) {
                        LightText(
                            "Sign out?\n\nYour vault, PIN and login are removed from this phone. Nothing changes on your server.",
                            variant = LightTextVariant.Copy,
                            align = TextAlign.Center,
                        )
                    }
                    LightBottomBar(
                        listOf(
                            LightBarButton.LightIcon(LightIcons.CLOSE, onClick = { viewModel.confirmingSignOut.value = false }, contentDescription = "Cancel"),
                            LightBarButton.Text("SIGN OUT", onClick = viewModel::signOut),
                            null,
                        ),
                    )
                } else {
                    Column(modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = 1f.gridUnitsAsDp())) {
                        SettingRow(if (syncing) "Syncing…" else syncLabel(lastSync), "Sync now", if (syncing) null else viewModel::syncNow)
                        SettingRow("Vault", "Lock now", viewModel::lockNow)
                        SettingRow(server?.removePrefix("https://") ?: "", email ?: "", null)
                        SettingRow("Account", "Sign out") { viewModel.confirmingSignOut.value = true }
                    }
                    LightText(
                        "Read-only. Edit your vault on a computer; changes sync here.",
                        variant = LightTextVariant.Detail,
                        lighten = true,
                        align = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth().padding(1f.gridUnitsAsDp()),
                    )
                }
            }
            message?.let { LightFullscreenModal(message = it, onClose = viewModel::dismissMessage) }
        }
    }

    private fun syncLabel(millis: Long?): String {
        if (millis == null) return "Not synced yet"
        val minutes = (System.currentTimeMillis() - millis) / 60_000
        return when {
            minutes < 1 -> "Synced just now"
            minutes < 60 -> "Synced $minutes min ago"
            minutes < 24 * 60 -> "Synced ${minutes / 60} hr ago"
            else -> "Synced ${minutes / (24 * 60)} days ago"
        }
    }
}

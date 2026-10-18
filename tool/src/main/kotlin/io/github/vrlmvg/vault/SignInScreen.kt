package io.github.vrlmvg.vault

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewModelScope
import com.thelightphone.sdk.LightScreen
import com.thelightphone.sdk.LightViewModel
import com.thelightphone.sdk.SealedLightActivity
import com.thelightphone.sdk.rememberKeyboardOptions
import com.thelightphone.sdk.ui.LightFullscreenModal
import com.thelightphone.sdk.ui.LightTextInputEditor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface SignInStep {
    data object Server : SignInStep
    data object Email : SignInStep
    data object Password : SignInStep
    data object TwoFactor : SignInStep
    data object Pin : SignInStep
    data object ConfirmPin : SignInStep
    data class Working(val text: String, val detail: String? = null) : SignInStep
    data object Done : SignInStep
}

class SignInViewModel(private val store: VaultStore) : LightViewModel<Unit>() {
    val step = MutableStateFlow<SignInStep>(SignInStep.Server)
    val session = MutableStateFlow(0)
    val message = MutableStateFlow<String?>(null)
    /** Pre-fill for the current input (server address / email when re-signing in). */
    val prefill = MutableStateFlow("")

    private var server = ""
    private var email = ""
    private var kdf: KdfConfig? = null
    private var passwordHash = ""
    private var userKey: SymmetricKey? = null
    private var token: TokenResponse? = null
    private var firstPin = ""

    init {
        viewModelScope.launch {
            store.server.first()?.let { server = it }
            store.email.first()?.let { email = it }
            go(SignInStep.Server, server.ifEmpty { "https://" })
        }
    }

    fun submitServer(text: CharSequence) {
        val url = text.toString().trim().trimEnd('/')
        if (!url.startsWith("https://") && !url.startsWith("http://") || url.length < 10) {
            return showError("Enter your server's full address, like https://vault.example.com")
        }
        server = url
        go(SignInStep.Email, email)
    }

    fun submitEmail(text: CharSequence) {
        val value = text.toString().trim()
        if (!value.contains('@')) return showError("Enter the email address of your account.")
        email = value
        working("Contacting server…")
        launch(onError = { go(SignInStep.Email, email) }) {
            kdf = VaultApi(server).use { it.prelogin(email) }
            go(SignInStep.Password)
        }
    }

    fun submitPassword(text: CharSequence) {
        val password = text.toString()
        val kdf = kdf ?: return go(SignInStep.Email, email)
        if (password.isEmpty()) return
        working("Checking master password…", "Your password is turned into a key on the phone; it never leaves it.")
        launch(onError = { go(SignInStep.Password) }) {
            val masterKey = withContext(Dispatchers.Default) { BitwardenCrypto.masterKey(password, email, kdf) }
            passwordHash = BitwardenCrypto.masterPasswordHash(masterKey, password)
            val result = VaultApi(server).use { it.login(email, passwordHash, store.deviceId()) }
            when (result) {
                is LoginResult.TwoFactorRequired -> {
                    masterKeyForLater = masterKey
                    if (VaultApi.TOTP_PROVIDER !in result.providers) {
                        throw VaultServerException("This account's two-step login method isn't supported here. Add an authenticator app in your vault's settings.")
                    }
                    go(SignInStep.TwoFactor)
                }
                is LoginResult.Success -> finishLogin(result.token, masterKey)
            }
        }
    }

    fun submitTwoFactor(text: CharSequence) {
        val code = text.toString().filter(Char::isDigit)
        if (code.length != 6) return showError("Enter the 6-digit code from your authenticator app.")
        working("Verifying code…")
        launch(onError = { go(SignInStep.TwoFactor) }) {
            when (val result = VaultApi(server).use { it.login(email, passwordHash, store.deviceId(), code) }) {
                is LoginResult.Success -> finishLogin(result.token, masterKeyForLater ?: throw VaultWrongPasswordException())
                is LoginResult.TwoFactorRequired -> throw VaultWrongCodeException()
            }
        }
    }

    fun submitPin(text: CharSequence) {
        val pin = text.toString()
        if (pin.length < 4) return showError("Use at least 4 characters for your PIN.")
        firstPin = pin
        go(SignInStep.ConfirmPin)
    }

    fun confirmPin(text: CharSequence) {
        if (text.toString() != firstPin) {
            firstPin = ""
            showError("The PINs didn't match. Choose a PIN again.")
            return go(SignInStep.Pin)
        }
        val key = userKey ?: return
        val token = token ?: return
        working("Downloading your vault…")
        launch(onError = { go(SignInStep.Pin) }) {
            store.saveAccount(server, email, token.refreshToken ?: throw VaultServerException("Server sent no refresh token."))
            store.setPin(firstPin, key)
            VaultSession.unlock(store, key)
            VaultSession.sync(store, token.accessToken)
            firstPin = ""
            step.value = SignInStep.Done
        }
    }

    fun dismissMessage() { message.value = null }

    override fun onBackPressed(): Boolean = when (step.value) {
        SignInStep.Server, SignInStep.Done -> false
        is SignInStep.Working -> true
        SignInStep.Email -> { go(SignInStep.Server, server); true }
        SignInStep.Password -> { go(SignInStep.Email, email); true }
        SignInStep.TwoFactor -> { go(SignInStep.Password); true }
        SignInStep.Pin, SignInStep.ConfirmPin -> { go(SignInStep.Pin); true }
    }

    private var masterKeyForLater: ByteArray? = null

    private fun finishLogin(token: TokenResponse, masterKey: ByteArray) {
        val protectedKey = token.protectedUserKey ?: throw VaultServerException("Server sent no account key.")
        userKey = BitwardenCrypto.decryptUserKey(protectedKey, masterKey)
        masterKey.fill(0)
        masterKeyForLater = null
        this.token = token
        go(SignInStep.Pin)
    }

    private fun launch(onError: () -> Unit, block: suspend () -> Unit) {
        viewModelScope.launch {
            try {
                block()
            } catch (e: Throwable) {
                onError()
                message.value = describeError(e)
            }
        }
    }

    private fun go(next: SignInStep, prefillText: String = "") {
        prefill.value = prefillText
        session.value++
        step.value = next
    }

    private fun working(text: String, detail: String? = null) { step.value = SignInStep.Working(text, detail) }
    private fun showError(text: String) { message.value = text }

    override fun onCleared() {
        masterKeyForLater?.fill(0)
        super.onCleared()
    }
}

private inline fun <T> VaultApi.use(block: (VaultApi) -> T): T = try { block(this) } finally { close() }

class SignInScreen(sealedActivity: SealedLightActivity) : LightScreen<Unit, SignInViewModel>(sealedActivity) {
    override val viewModelClass: Class<SignInViewModel>
        get() = SignInViewModel::class.java

    override fun createViewModel() = SignInViewModel(VaultSession.store(lightContext))

    @Composable
    override fun Content() {
        val step by viewModel.step.collectAsState()
        val session by viewModel.session.collectAsState()
        val prefill by viewModel.prefill.collectAsState()
        val message by viewModel.message.collectAsState()
        val field = rememberTextFieldState("")
        val keyboardOptionsFlow = rememberKeyboardOptions()

        LaunchedEffect(session) {
            if (prefill.isEmpty()) field.clearText() else field.setTextAndPlaceCursorAtEnd(prefill)
        }
        LaunchedEffect(step) { if (step == SignInStep.Done) goBack() }

        @Composable
        fun editor(title: String, submit: String, onSubmit: (CharSequence) -> Unit) = LightTextInputEditor(
            title = title,
            state = field,
            keyboardOptionsFlow = keyboardOptionsFlow,
            onSubmit = onSubmit,
            onBack = { goBack() },
            submitLabel = submit,
            singleLine = true,
            editorKey = session,
            modifier = Modifier.fillMaxSize(),
        )

        VaultTheme {
            when (val s = step) {
                SignInStep.Server -> editor("Server address", "NEXT", viewModel::submitServer)
                SignInStep.Email -> editor("Email", "NEXT", viewModel::submitEmail)
                SignInStep.Password -> editor("Master password", "SIGN IN", viewModel::submitPassword)
                SignInStep.TwoFactor -> editor("Authenticator code", "VERIFY", viewModel::submitTwoFactor)
                SignInStep.Pin -> editor("Choose a PIN", "NEXT", viewModel::submitPin)
                SignInStep.ConfirmPin -> editor("Repeat PIN", "SAVE", viewModel::confirmPin)
                is SignInStep.Working -> Column(Modifier.fillMaxSize()) {
                    TopBar("Sign in", onBack = null)
                    Working(s.text, s.detail)
                }
                SignInStep.Done -> Unit
            }
            message?.let { LightFullscreenModal(message = it, onClose = viewModel::dismissMessage) }
        }
    }
}

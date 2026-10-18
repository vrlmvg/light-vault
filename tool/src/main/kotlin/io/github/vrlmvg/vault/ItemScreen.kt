package io.github.vrlmvg.vault

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.thelightphone.sdk.SealedLightActivity
import com.thelightphone.sdk.SimpleLightScreen
import com.thelightphone.sdk.ui.LightScrollView
import com.thelightphone.sdk.ui.LightText
import com.thelightphone.sdk.ui.LightTextVariant
import com.thelightphone.sdk.ui.gridUnitsAsDp
import com.thelightphone.sdk.ui.lightClickable
import kotlinx.coroutines.delay

/** Read-only view of one vault item. Secrets stay hidden until tapped. */
class ItemScreen(sealedActivity: SealedLightActivity, private val itemId: String) : SimpleLightScreen<Unit>(sealedActivity) {

    @Composable
    override fun Content() {
        val state by VaultSession.state.collectAsState()
        val item = (state as? VaultSession.State.Unlocked)?.vault?.items?.firstOrNull { it.id == itemId }
        LaunchedEffect(item == null) { if (item == null) goBack() }
        item ?: return

        VaultTheme {
            Column(modifier = Modifier.fillMaxSize()) {
                TopBar(item.name, onBack = { goBack() })
                LightScrollView(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .padding(horizontal = 1f.gridUnitsAsDp()),
                ) {
                    item.folder?.let { Field(ItemField("Folder", it)) }
                    item.fields.forEach { Field(it) }
                    if (item.fields.isEmpty()) {
                        LightText("Nothing else is stored in this item.", variant = LightTextVariant.Detail, lighten = true)
                    }
                }
            }
        }
    }
}

@Composable
private fun Field(field: ItemField) {
    var revealed by remember(field) { mutableStateOf(false) }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (field.kind == FieldKind.Secret) Modifier.lightClickable { revealed = !revealed } else Modifier)
            .padding(bottom = 1.5f.gridUnitsAsDp()),
    ) {
        LightText(
            text = if (field.kind == FieldKind.Secret) "${field.label} · tap to ${if (revealed) "hide" else "show"}" else field.label,
            variant = LightTextVariant.Detail,
            lighten = true,
        )
        when (field.kind) {
            FieldKind.Secret -> LightText(
                text = if (revealed) field.value else "••••••••",
                variant = LightTextVariant.Heading,
                monospace = revealed,
            )
            FieldKind.Totp -> TotpValue(field.value)
            FieldKind.Notes -> LightText(field.value, variant = LightTextVariant.Copy)
            else -> LightText(field.value, variant = LightTextVariant.Copy)
        }
    }
}

/** Live verification code from an otpauth:// link or a bare base32 secret. */
@Composable
private fun TotpValue(raw: String) {
    val account = remember(raw) { totpAccount(raw) }
    var now by remember { mutableStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            now = System.currentTimeMillis() / 1000
        }
    }
    if (account == null) {
        LightText("This code type isn't supported.", variant = LightTextVariant.Copy)
        return
    }
    val code = remember(account, now / account.period) {
        runCatching { TotpGenerator.generate(account.secret, account.digits, account.period, account.algorithm, now) }.getOrNull()
    }
    if (code == null) {
        LightText("Invalid secret.", variant = LightTextVariant.Copy)
        return
    }
    val remaining = account.period - (now % account.period)
    LightText(code.code.chunked(3).joinToString(" "), variant = LightTextVariant.Title)
    LightText("Changes in ${remaining}s", variant = LightTextVariant.Detail, lighten = true)
}

internal fun totpAccount(raw: String): Account? {
    val value = raw.trim()
    if (value.startsWith("otpauth://", ignoreCase = true)) return OtpAuthUriParser.parse(value).getOrNull()
    if (value.startsWith("steam://", ignoreCase = true)) return null
    val secret = value.replace(" ", "").uppercase()
    if (secret.isEmpty()) return null
    return Account(issuer = "", label = "", secret = secret, digits = 6, period = 30)
}

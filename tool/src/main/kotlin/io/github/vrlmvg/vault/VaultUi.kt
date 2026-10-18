package io.github.vrlmvg.vault

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import com.thelightphone.sdk.ui.LightBarButton
import com.thelightphone.sdk.ui.LightIcons
import com.thelightphone.sdk.ui.LightProgressBar
import com.thelightphone.sdk.ui.LightText
import com.thelightphone.sdk.ui.LightTextVariant
import com.thelightphone.sdk.ui.LightTheme
import com.thelightphone.sdk.ui.LightThemeController
import com.thelightphone.sdk.ui.LightThemeTokens
import com.thelightphone.sdk.ui.LightTopBar
import com.thelightphone.sdk.ui.LightTopBarCenter
import com.thelightphone.sdk.ui.gridUnitsAsDp
import com.thelightphone.sdk.ui.lightClickable

@Composable
fun VaultTheme(content: @Composable () -> Unit) {
    val colors by LightThemeController.colors.collectAsState()
    LightTheme(colors = colors) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(LightThemeTokens.colors.background),
        ) { content() }
    }
}

@Composable
fun TopBar(title: String, onBack: (() -> Unit)?, right: LightBarButton? = null) {
    LightTopBar(
        leftButton = onBack?.let { LightBarButton.LightIcon(icon = LightIcons.BACK, onClick = it, contentDescription = "Back") },
        center = LightTopBarCenter.Text(title),
        rightButton = right,
        modifier = Modifier.padding(bottom = 0.5f.gridUnitsAsDp()),
    )
}

@Composable
fun ColumnScope.CenteredMessage(text: String, action: String? = null, onAction: (() -> Unit)? = null) {
    Column(
        modifier = Modifier
            .weight(1f)
            .fillMaxWidth()
            .padding(horizontal = 1f.gridUnitsAsDp()),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        LightText(text, variant = LightTextVariant.Copy, align = TextAlign.Center)
        if (action != null && onAction != null) {
            LightText(
                text = action,
                variant = LightTextVariant.Button,
                underline = true,
                modifier = Modifier
                    .padding(top = 1.5f.gridUnitsAsDp())
                    .lightClickable(onClick = onAction)
                    .padding(0.5f.gridUnitsAsDp()),
            )
        }
    }
}

@Composable
fun ColumnScope.Working(text: String, detail: String? = null, progress: Float? = null) {
    Column(
        modifier = Modifier
            .weight(1f)
            .fillMaxWidth()
            .padding(horizontal = 2f.gridUnitsAsDp()),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        LightText(text, variant = LightTextVariant.Copy, align = TextAlign.Center)
        progress?.let {
            Box(Modifier.padding(vertical = 1f.gridUnitsAsDp())) { LightProgressBar(colors = LightThemeTokens.colors, progress = it) }
        }
        detail?.let {
            LightText(it, variant = LightTextVariant.Detail, lighten = true, align = TextAlign.Center,
                modifier = Modifier.padding(top = 1f.gridUnitsAsDp()))
        }
    }
}

/** A list entry: primary text, then a smaller, lightened second line (LightOS hierarchy). */
@Composable
fun ListRow(title: String, subtitle: String?, onClick: (() -> Unit)?) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.lightClickable(onClick = onClick) else Modifier)
            .padding(vertical = 0.75f.gridUnitsAsDp()),
    ) {
        LightText(title, variant = LightTextVariant.Copy, maxLines = 1, overflow = TextOverflow.Ellipsis)
        subtitle?.takeIf { it.isNotBlank() }?.let {
            LightText(it, variant = LightTextVariant.Detail, lighten = true, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

/** Settings-style row: small lightened label above a larger value. */
@Composable
fun SettingRow(label: String, value: String, onClick: (() -> Unit)?) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.lightClickable(onClick = onClick) else Modifier)
            .padding(vertical = 0.75f.gridUnitsAsDp()),
    ) {
        LightText(label, variant = LightTextVariant.Detail, lighten = true)
        LightText(value, variant = LightTextVariant.Heading, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

fun describeError(e: Throwable): String = when (e) {
    is VaultWrongPasswordException, is VaultWrongCodeException, is VaultSessionExpiredException,
    is VaultServerException, is WrongPinException, is PinWipedException -> e.message!!
    is VaultCryptoException -> "Couldn't decrypt your vault. Check your master password."
    is OutOfMemoryError -> "Not enough memory for your account's key settings."
    else -> "Couldn't reach your server. Check the address and your connection."
}

package io.github.vrlmvg.vault

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.Base64
import java.util.concurrent.TimeUnit

class VaultWrongPasswordException(message: String? = null) : Exception(message ?: "Email or master password is incorrect.")
class VaultWrongCodeException : Exception("That two-step login code is incorrect.")
class VaultSessionExpiredException : Exception("Your login has expired. Sign in again.")
class VaultServerException(message: String) : Exception(message)

data class TokenResponse(
    val accessToken: String,
    val refreshToken: String?,
    val protectedUserKey: String?,
)

sealed interface LoginResult {
    data class Success(val token: TokenResponse) : LoginResult
    data class TwoFactorRequired(val providers: List<Int>) : LoginResult
}

/** The Bitwarden endpoints Vaultwarden implements that a read-only client needs. */
class VaultApi(server: String) {
    private val base = server.trim().trimEnd('/')
    private val json = Json { ignoreUnknownKeys = true }
    private val client = HttpClient(OkHttp) {
        expectSuccess = false
        engine {
            config {
                connectTimeout(15, TimeUnit.SECONDS)
                readTimeout(30, TimeUnit.SECONDS)
                writeTimeout(30, TimeUnit.SECONDS)
            }
        }
    }

    suspend fun prelogin(email: String): KdfConfig {
        val body = buildJsonObject { put("email", email.trim()) }.toString()
        var response = postJson("/identity/accounts/prelogin", body)
        if (response.status == HttpStatusCode.NotFound) response = postJson("/api/accounts/prelogin", body)
        val o = parse(ensureOk(response))
        val type = o.int("kdf") ?: KdfConfig.PBKDF2
        return KdfConfig(
            type = type,
            iterations = o.int("kdfIterations") ?: if (type == KdfConfig.ARGON2ID) 3 else 600_000,
            memoryMiB = o.int("kdfMemory"),
            parallelism = o.int("kdfParallelism"),
        ).also {
            // A hostile server could ask for weak settings to make the password hash it receives easy to crack.
            if (!it.isSafe()) throw VaultServerException("Your server asked for unsafe key settings. Sign-in stopped.")
        }
    }

    suspend fun login(
        email: String,
        masterPasswordHash: String,
        deviceId: String,
        twoFactorCode: String? = null,
        twoFactorProvider: Int = TOTP_PROVIDER,
    ): LoginResult {
        val response = client.submitForm(
            url = "$base/identity/connect/token",
            formParameters = parameters {
                append("grant_type", "password")
                append("username", email.trim())
                append("password", masterPasswordHash)
                append("scope", "api offline_access")
                append("client_id", CLIENT_ID)
                append("deviceType", DEVICE_TYPE_ANDROID)
                append("deviceIdentifier", deviceId)
                append("deviceName", DEVICE_NAME)
                if (twoFactorCode != null) {
                    append("twoFactorToken", twoFactorCode)
                    append("twoFactorProvider", twoFactorProvider.toString())
                    append("twoFactorRemember", "0")
                }
            },
        ) {
            // Bitwarden's cloud requires this; Vaultwarden ignores it.
            header("Auth-Email", Base64.getUrlEncoder().withoutPadding().encodeToString(email.trim().toByteArray()))
        }
        val text = response.bodyAsText()
        val body = runCatching { parse(text) }.getOrNull()
        if (response.status.isSuccess() && body != null) return LoginResult.Success(token(body))

        val providers = body?.array("twoFactorProviders")?.mapNotNull { it.toString().trim('"').toIntOrNull() }.orEmpty()
        return when {
            providers.isNotEmpty() && twoFactorCode == null -> LoginResult.TwoFactorRequired(providers)
            twoFactorCode != null && response.status == HttpStatusCode.BadRequest -> throw VaultWrongCodeException()
            response.status == HttpStatusCode.BadRequest -> throw VaultWrongPasswordException(errorMessage(body))
            else -> throw VaultServerException("Server returned HTTP ${response.status.value}.")
        }
    }

    suspend fun refresh(refreshToken: String): TokenResponse {
        val response = client.submitForm(
            url = "$base/identity/connect/token",
            formParameters = parameters {
                append("grant_type", "refresh_token")
                append("client_id", CLIENT_ID)
                append("refresh_token", refreshToken)
            },
        )
        if (response.status == HttpStatusCode.BadRequest || response.status == HttpStatusCode.Unauthorized) {
            throw VaultSessionExpiredException()
        }
        return token(parse(ensureOk(response)))
    }

    suspend fun sync(accessToken: String): String {
        val response = client.get("$base/api/sync") {
            header("Authorization", "Bearer $accessToken")
            parameter("excludeDomains", "true")
        }
        if (response.status == HttpStatusCode.Unauthorized) throw VaultSessionExpiredException()
        return ensureOk(response)
    }

    fun close() = client.close()

    private suspend fun postJson(path: String, body: String): HttpResponse = client.post(base + path) {
        contentType(ContentType.Application.Json)
        setBody(body)
    }

    private suspend fun ensureOk(response: HttpResponse): String {
        val text = response.bodyAsText()
        if (!response.status.isSuccess()) {
            throw VaultServerException(errorMessage(runCatching { parse(text) }.getOrNull()) ?: "Server returned HTTP ${response.status.value}.")
        }
        return text
    }

    private fun parse(text: String): JsonObject = VaultDecryptor.normaliseKeys(json.parseToJsonElement(text)) as JsonObject

    private fun token(o: JsonObject) = TokenResponse(
        accessToken = o.str("access_token") ?: throw VaultServerException("Login response had no access token."),
        refreshToken = o.str("refresh_token"),
        protectedUserKey = o.str("key"),
    )

    private fun errorMessage(body: JsonObject?): String? =
        body?.obj("errorModel")?.str("message") ?: body?.str("message") ?: body?.str("error_description")

    companion object {
        const val TOTP_PROVIDER = 0
        private const val CLIENT_ID = "mobile"
        private const val DEVICE_TYPE_ANDROID = "0"
        private const val DEVICE_NAME = "Light Phone"
    }
}

package io.github.vrlmvg.vault

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import java.util.Base64

enum class ItemType(val code: Int, val label: String) {
    Login(1, "Login"),
    SecureNote(2, "Note"),
    Card(3, "Card"),
    Identity(4, "Identity"),
    SshKey(5, "SSH key");

    companion object {
        fun from(code: Int?): ItemType? = entries.firstOrNull { it.code == code }
    }
}

enum class FieldKind { Text, Secret, Totp, Url, Notes }

data class ItemField(val label: String, val value: String, val kind: FieldKind = FieldKind.Text)

data class VaultItem(
    val id: String,
    val type: ItemType,
    val name: String,
    /** Second line in lists: username, card brand and last digits, etc. */
    val subtitle: String?,
    val folder: String?,
    val fields: List<ItemField>,
    val favorite: Boolean,
) {
    val totp: String? get() = fields.firstOrNull { it.kind == FieldKind.Totp }?.value
}

data class DecryptedVault(val items: List<VaultItem>, val failed: Int)

/**
 * Turns a Bitwarden/Vaultwarden /api/sync response into readable items. Everything happens in memory;
 * [userKey] is the account's symmetric key.
 */
object VaultDecryptor {
    private val json = Json { ignoreUnknownKeys = true }

    fun decrypt(syncJson: String, userKey: SymmetricKey): DecryptedVault {
        val root = normaliseKeys(json.parseToJsonElement(syncJson)) as JsonObject
        val profile = root.obj("profile")
        val orgKeys = organizationKeys(profile, userKey)
        val folders = root.array("folders").mapNotNull { folder ->
            val o = folder as? JsonObject ?: return@mapNotNull null
            val id = o.str("id") ?: return@mapNotNull null
            id to (o.str("name")?.let { runCatching { EncString.parse(it).decryptString(userKey) }.getOrNull() } ?: "")
        }.toMap()

        var failed = 0
        val items = root.array("ciphers").mapNotNull { element ->
            val cipher = element as? JsonObject ?: return@mapNotNull null
            if (cipher.str("deletedDate") != null) return@mapNotNull null
            val type = ItemType.from(cipher.int("type")) ?: return@mapNotNull null
            runCatching {
                val ownerKey = cipher.str("organizationId")?.let { orgKeys[it] ?: throw VaultCryptoException("No key for organization") }
                    ?: userKey
                val key = cipher.str("key")?.let { SymmetricKey.fromBytes(EncString.parse(it).decryptWith(ownerKey)) } ?: ownerKey
                decryptItem(cipher, type, key, cipher.str("folderId")?.let(folders::get))
            }.getOrElse {
                failed++
                null
            }
        }.sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.name })
        return DecryptedVault(items, failed)
    }

    private fun organizationKeys(profile: JsonObject?, userKey: SymmetricKey): Map<String, SymmetricKey> {
        val orgs = profile?.array("organizations").orEmpty()
        if (orgs.isEmpty()) return emptyMap()
        val privateKey = profile?.str("privateKey")?.let { EncString.parse(it).decryptWith(userKey) } ?: return emptyMap()
        return orgs.mapNotNull { element ->
            val org = element as? JsonObject ?: return@mapNotNull null
            val id = org.str("id") ?: return@mapNotNull null
            val key = org.str("key") ?: return@mapNotNull null
            runCatching { id to SymmetricKey.fromBytes(BitwardenCrypto.decryptWithPrivateKey(key, privateKey)) }.getOrNull()
        }.toMap()
    }

    private fun decryptItem(cipher: JsonObject, type: ItemType, key: SymmetricKey, folder: String?): VaultItem {
        fun dec(value: String?): String? = value?.takeIf { it.isNotEmpty() }?.let { EncString.parse(it).decryptString(key) }
        fun JsonObject.dec(name: String) = dec(str(name))?.takeIf { it.isNotBlank() }

        val fields = mutableListOf<ItemField>()
        var subtitle: String? = null

        when (type) {
            ItemType.Login -> cipher.obj("login")?.let { login ->
                val username = login.dec("username")
                subtitle = username
                username?.let { fields += ItemField("Username", it) }
                login.dec("password")?.let { fields += ItemField("Password", it, FieldKind.Secret) }
                login.dec("totp")?.let { fields += ItemField("Verification code", it, FieldKind.Totp) }
                login.array("uris").forEachIndexed { i, uri ->
                    (uri as? JsonObject)?.dec("uri")?.let {
                        fields += ItemField(if (i == 0) "Website" else "Website ${i + 1}", it, FieldKind.Url)
                    }
                }
            }
            ItemType.Card -> cipher.obj("card")?.let { card ->
                val number = card.dec("number")
                val brand = card.dec("brand")
                subtitle = listOfNotNull(brand, number?.takeLast(4)?.let { "•••• $it" }).joinToString(" ").ifEmpty { null }
                card.dec("cardholderName")?.let { fields += ItemField("Cardholder", it) }
                number?.let { fields += ItemField("Number", it.chunked(4).joinToString(" "), FieldKind.Secret) }
                val month = card.dec("expMonth")
                val year = card.dec("expYear")
                if (month != null || year != null) {
                    fields += ItemField("Expires", listOfNotNull(month?.padStart(2, '0'), year).joinToString(" / "))
                }
                card.dec("code")?.let { fields += ItemField("Security code", it, FieldKind.Secret) }
                brand?.let { fields += ItemField("Brand", it) }
            }
            ItemType.Identity -> cipher.obj("identity")?.let { id ->
                val fullName = listOfNotNull(id.dec("title"), id.dec("firstName"), id.dec("middleName"), id.dec("lastName"))
                    .joinToString(" ").ifEmpty { null }
                subtitle = fullName
                fullName?.let { fields += ItemField("Name", it) }
                listOf(
                    "email" to "Email", "phone" to "Phone", "username" to "Username", "company" to "Company",
                    "ssn" to "Social security number", "passportNumber" to "Passport", "licenseNumber" to "Licence",
                ).forEach { (field, label) ->
                    id.dec(field)?.let { fields += ItemField(label, it, if (field in SENSITIVE_IDENTITY) FieldKind.Secret else FieldKind.Text) }
                }
                val address = listOfNotNull(
                    id.dec("address1"), id.dec("address2"), id.dec("address3"),
                    listOfNotNull(id.dec("postalCode"), id.dec("city")).joinToString(" ").ifEmpty { null },
                    id.dec("state"), id.dec("country"),
                ).joinToString("\n")
                if (address.isNotEmpty()) fields += ItemField("Address", address)
            }
            ItemType.SshKey -> cipher.obj("sshKey")?.let { ssh ->
                ssh.dec("keyFingerprint")?.let { subtitle = it; fields += ItemField("Fingerprint", it) }
                ssh.dec("publicKey")?.let { fields += ItemField("Public key", it) }
                ssh.dec("privateKey")?.let { fields += ItemField("Private key", it, FieldKind.Secret) }
            }
            ItemType.SecureNote -> Unit
        }

        cipher.array("fields").forEach { element ->
            val field = element as? JsonObject ?: return@forEach
            val name = field.dec("name") ?: "Field"
            val value = field.dec("value") ?: return@forEach
            // Custom field types: 0 text, 1 hidden, 2 boolean, 3 linked.
            fields += ItemField(name, value, if (field.int("type") == 1) FieldKind.Secret else FieldKind.Text)
        }
        cipher.dec("notes")?.let { fields += ItemField("Notes", it, FieldKind.Notes) }

        return VaultItem(
            id = cipher.str("id") ?: "",
            type = type,
            name = cipher.dec("name") ?: "(no name)",
            subtitle = subtitle,
            folder = folder,
            fields = fields,
            favorite = (cipher["favorite"] as? JsonPrimitive)?.contentOrNull == "true",
        )
    }

    /**
     * Bitwarden's token response uses PascalCase, sync uses camelCase (varies by server version),
     * so keys are lower-camel-cased before reading.
     */
    internal fun normaliseKeys(element: JsonElement): JsonElement = when (element) {
        is JsonObject -> JsonObject(element.entries.associate { (k, v) -> k.replaceFirstChar(Char::lowercaseChar) to normaliseKeys(v) })
        is JsonArray -> JsonArray(element.map(::normaliseKeys))
        else -> element
    }

    private val SENSITIVE_IDENTITY = setOf("ssn", "passportNumber", "licenseNumber")
}

internal fun JsonObject.obj(name: String): JsonObject? = this[name] as? JsonObject
internal fun JsonObject.array(name: String): List<JsonElement> = (this[name] as? JsonArray).orEmpty()
internal fun JsonObject.str(name: String): String? =
    (this[name] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.contentOrNull
internal fun JsonObject.int(name: String): Int? = (this[name] as? JsonPrimitive)?.intOrNull

internal fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)

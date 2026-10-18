package io.github.vrlmvg.vault

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Fixture built independently in Python (`cryptography`) the way Bitwarden clients encrypt a vault. */
class VaultDecryptorTest {
    private val fixture = Json.parseToJsonElement(FIXTURE).jsonObject

    private fun unlock(): DecryptedVault {
        val prelogin = fixture["prelogin"]!!.jsonObject
        val kdf = KdfConfig(KdfConfig.PBKDF2, prelogin["kdfIterations"]!!.jsonPrimitive.content.toInt())
        val password = fixture["password"]!!.jsonPrimitive.content
        val masterKey = BitwardenCrypto.masterKey(password, fixture["email"]!!.jsonPrimitive.content, kdf)
        assertEquals(fixture["masterPasswordHash"]!!.jsonPrimitive.content, BitwardenCrypto.masterPasswordHash(masterKey, password))

        val token = VaultDecryptor.normaliseKeys(fixture["token"]!!) as JsonObject
        val userKey = BitwardenCrypto.decryptUserKey(token["key"]!!.jsonPrimitive.content, masterKey)
        return VaultDecryptor.decrypt(fixture["sync"].toString(), userKey)
    }

    @Test
    fun decryptsWholeVault() {
        val vault = unlock()
        assertEquals(0, vault.failed)
        // Deleted item is left out; the rest sorted by name.
        assertEquals(listOf("Bank (shared)", "GitHub", "Mastodon", "Me", "Visa", "Wi-Fi"), vault.items.map { it.name })
    }

    @Test
    fun loginFields() {
        val github = unlock().items.first { it.name == "GitHub" }
        assertEquals("alice", github.subtitle)
        assertEquals("Work", github.folder)
        val byLabel = github.fields.associateBy { it.label }
        assertEquals("gh-Pa55word!", byLabel["Password"]!!.value)
        assertEquals(FieldKind.Secret, byLabel["Password"]!!.kind)
        assertTrue(github.totp!!.startsWith("otpauth://totp/GitHub"))
        assertEquals("https://github.com/login", byLabel["Website"]!!.value)
        assertEquals("https://github.com", byLabel["Website 2"]!!.value)
        assertEquals(FieldKind.Secret, byLabel["Recovery code"]!!.kind)
        assertEquals("Pro", byLabel["Plan"]!!.value)
        assertEquals("2FA via authenticator", byLabel["Notes"]!!.value)
    }

    @Test
    fun organisationAndItemKeys() {
        val items = unlock().items.associateBy { it.name }
        assertEquals("Sh4red-B4nk", items["Bank (shared)"]!!.fields.first { it.label == "Password" }.value)
        assertEquals("toot-toot", items["Mastodon"]!!.fields.first { it.label == "Password" }.value)
    }

    @Test
    fun cardNoteAndIdentity() {
        val items = unlock().items.associateBy { it.name }
        val card = items["Visa"]!!
        assertEquals("Visa •••• 1111", card.subtitle)
        assertEquals("4111 1111 1111 1111", card.fields.first { it.label == "Number" }.value)
        assertEquals("07 / 2029", card.fields.first { it.label == "Expires" }.value)
        assertNull(items["Wi-Fi"]!!.subtitle)
        assertEquals("SSID: home\nPassword: hunter2", items["Wi-Fi"]!!.fields.single().value)
        val me = items["Me"]!!
        assertEquals("Alice Example", me.subtitle)
        assertEquals("2000 Sydney", me.fields.first { it.label == "Address" }.value)
        assertEquals(FieldKind.Secret, me.fields.first { it.label == "Passport" }.kind)
    }

    private companion object {
        const val FIXTURE = """{"email": "alice@example.com", "password": "correct horse", "masterPasswordHash": "isbNZTautBnoDcgUG02H2O4dD5lyVmF2ArQzr/O2ZsE=", "prelogin": {"kdf": 0, "kdfIterations": 5000, "kdfMemory": null, "kdfParallelism": null}, "token": {"access_token": "fake-access", "expires_in": 7200, "token_type": "Bearer", "refresh_token": "fake-refresh", "Key": "2.fkjWc75ZDe74mXWi5N1APg==|TOGyEmzQImjoaC9bwHZBzuFpQ3riA/gC4E3nWASCWpcfaAfjvit0OmC+HWbWnHy/mBeu9mOf++UDEauYai5lbUQzDNn4JF/9YHKa9vmr0SY=|wz8fFlR7jR54gmgseIw1X2I6xev7o63sBpL7vCU45+o=", "PrivateKey": "2.Cf2D/iAOzOpDek/6sQPdBg==|910mSEA1TSQ289YzKoqBz8bbKe3xjAABWEpGdP+sjoS6SBh9O1gknY/8lxMmEpezvU3Ri226EWyOKTFBIxFWIYyxZVtJnyHPs6mb1JLeFF6WtRSWlxdmx0x7NwcVuS7uBg/uV9EvgbzcHStsg01Yt0/KnzISdSNAHPzvcRU8GN41Ln3X1CIdPRRTBbhDSIZ7lbH9J5MPXLhbnTVVrFM8DCoZGQYop7L4kTESjPTSMSXMmzNHqXM+9U/WCmjMpFh7usNVcM5v2puGONEAyiyM0ALf6HCeRLyaekDNv9aWP494DT8dKHE+E5JtgEXYwxGRPSK/HNpakC7ORLUXRrwpKUwaceShQTRsvEK2+t+e9NhqJ2IXncrTm+SsgpMgxvCbvntf1TlAOyPO97cHcdeGSpQBHBwRjvbbjyGK0FEBbXBn5fRLz7ln7igFxYKFUjmb8+CX2dvUjDzlqWFl0eWK2MfZURsqIkD1kGnbkCJnO03MfPShrpbCpPXyETvY+atJfpfRx0v/ordEwExMD0okdwM4SN8tKhJnASuFMa2aNKicmzIAMW4czokf2BmXh4lOqzRGvoaDbIzsb2s2Iy0D7VAQ7ddk4P2z8LsKvrE6VzChVvndZp+8quP8yME8EhQ1CikgHLPszSMfghQcc+Gq1IfT6CwLYDaiv/FTYc9nyzz3PP5SVmCWW5UTeNxBCL25MYEY2g3+6TJtEbG0psqC/Pf2VYl/FN5WRlzbnEJPr2NTX0g/NgmbKZh3Xo/8aHyw7eKG4qsUY018UpSw70budtPLWlF/a+GJs/TClMJkCoWlCiqMZFUF7xeMjuzZbvu+wjpqLlPJxXWCeVmTrImoQrDnUYr5jh7svNPH77o3HTxvWq8PFazhRgWVWVcRNXlpHRdIx3hO8j6tKCDE6HU8T0pc/t4zDkkfJOJ7CGweUYqT3fgV0z3FUvTAiI+FugyGHz9J4cEJrO3VONS3K+C6CD1PlUn0iny2RutaTWQ9q5b66Kz/09qYW7U6rCwTHE8ZeDU8IunmeGLMdu2pnVBNBVcf49BjbYsACr5h7YvomPu7KnWgpx5q2zd01PXJsZ4XDcpY5mxcR835h3u+NN37VbzmG/wQM72pEHfBdnRZEMfEuCUsWbMOZbC5Z93gsD8byKGssqp7Msy6EexltI+XNHqFEV+aCD5zV0Tyiw8QzQhLR/vf8P2+KaFeKDQ4Vtw99LwlVq/g/X2ItwuHsDlU/0Jqhnt1DPeMqw+9TbHjREGrxAXU/rxCRq7So8nOxWUSujTnEoruNFUj3/kX7xuKU0VFNP9Y5UMZzKe8MORrih/tTD4qiDDa2tnQq57N7SQ30GG6W9HWKb1uNCoqNhytrgQU6JWfIybLGjdeOLnI5DYj+pE+JMWhLOnWSSQS5hIlZJDZHwZA7KOVLDXoXhbvdtbuMI3Eh7nyp0+6h+2dKa7+rDkaQudEpH6v/Xx1mASiPxtb26bg0KqTylVDH8eWKJH+5tuIV2sxMZo15j5UjoMRvB2Wt28njyIPCgDbemJjRsJS9wvZ+olJvNG5guP7h1HnNAfIz81XL3HD10i3DSA6DNNL0mB5EzugpDYMGLI8DaxiQI8h2x2jgA3eQEAdpiutRM3/2zYMpGmUPQgxadI=|6GSLmuhTsK1HKpheqS7jWXbsVmEWwCQpjlopVXdF01U=", "Kdf": 0, "KdfIterations": 5000, "KdfMemory": null, "KdfParallelism": null, "ResetMasterPassword": false, "scope": "api offline_access"}, "sync": {"object": "sync", "profile": {"id": "u-1", "email": "alice@example.com", "key": "2.fkjWc75ZDe74mXWi5N1APg==|TOGyEmzQImjoaC9bwHZBzuFpQ3riA/gC4E3nWASCWpcfaAfjvit0OmC+HWbWnHy/mBeu9mOf++UDEauYai5lbUQzDNn4JF/9YHKa9vmr0SY=|wz8fFlR7jR54gmgseIw1X2I6xev7o63sBpL7vCU45+o=", "privateKey": "2.Gbi244BjcTZWfZfRfajeYg==|YR8UITnk5DWx2l2Bz59DZRDEZ3JO862ywndWdrczxmBDnF/FW6ND8/e7jT78zsHLeT3usfQpIbjLWHSKio6Y1irPk5JRZeEb0jk2KmjCtaa3jZLOGMjMaY2NJRw3/o0xfrSG4LM8Elh7tl7cR2Rmv2id99L4BL424SRNsIQZk5z3G5fCYSvNj/K+ArWdO18jB33MqN6X9ehGAqZf9Hou/g8rocM72kM6JsGRdCJPVGcVADDTEnoyhWPR11ENnOp6FZLisVNqWM7/wJ5xeSz8SUNE0Pm582RLEUJbZjiXX8E7IZV5Vm4SkZa8aCEwlhqpMJ89RpG+/emWduRGUav1F3UU+N2y2s25pX5I0uFlZUVzeEwfER/CVlJOSqhQwVQfzKJgpdjtXjf1d8T5Z0sI6s7iecqnNXjPrwAT2JegYVLf7+QxAnkN7R6LtSO5FYKaBIeBVzNztzp2af2NU1ORmhF6EDOlZbtqffMC6EbT9ffsYlV379uoxdXoPgMF4iHWavBXoTa35w0gT19yK6Q9yRWOoXz2YWOI89QbxKhguGKpuaA+KoIgIXzL+tNA2kt9Ya4zqI00yMKEV1uwQ+o1B4XfmVy+T3lYZt8iPUErrfxFEdTFN7r1GzecUEMhllTtIm094TLPNgIO8S8rZq0AjiUWyuPb5gcawAeGpMkRwzaal1H5lI4e8Znfq8a1VxecXUb6TIephyicK57r3Ui+zLyc8LTly9Mnv3RgV7zCADlHHefHZdlEXk0sVg2eIGIDdkD19hzgt8TwljQZzMmx8fUmCvuWh8ICsMUzW/1nqXH+OP3SKzTG4DfRHyQZ09ZT+EP6UKq9T0sS7EWd93Gfeae5h3F8RHG9am2eBTuEKE1tkCpXP07GGaHmEi+zbBYseLKr4GWLfawonnZPeD7jElalN2wICBcBEjqbB+Ddc3Vl4B6OiTDVChRP+HSnqOfHyI1RVh+sOZHUFn2btXsO1EJFVoBAx/BWvpOBAlvKiCAh+3T2fxKekdnitm0vP6r6o+/Bmmk76JVnxMklU5ulF107+j7WT4lBC+CgsX2hXAxfHx10YTjQ6Bpp7gdmhsk+8GPqmMyFa5QphshkPSzIBfzJsv7GhFighu9lwERh48X5tZ0oNt4Gv1BJDuXvNNvIOIjP+0efDvGKy8J6xkVepb3BmgqUiLHTmrdaPOhU8NAp9mWlia8KY4EO+LTt8jfTG37mfqH7p8M3Ht7bHA0X82beMWj7sUW+jxDpOAzd4EapzJ0L9+dTlTdPK6FBa88xnRYZO9Az7Es9iSv4tHxY/MW3dIist6Im5YXv5wAF28hy7jOV/o26MTf0e0dpaQGjWr9wio4uH6psC8texeKRE0QNGQuJCPFNuwhHgymXLEs4Tjun1VftMnkl/h2wWN+YfmUdCHORlVxvX8b0SRe5SV7hYFeZVo7AYqrYHkgou2BpEL0DrV/LKzwh6uorqz0tIC2F1+QxOJvwsXH461F0140r0hP/NqjJSYzgM90MnIbshY3on/sjJAvCpwfkfFndtW8pjqK8juWU+EokOEhPrBZwpnTGH/LrjLbNnnVf4aGNCeqUBVl8EtI2eE5oaiXiTptCjEjH2nQ7coiHIUJ8L3QSC5XAO7zQ7M1xjOvcesI=|iivyKqSL72yXI2stZ1r47YMpQRcV8z2ngJidE1Yvb/E=", "organizations": [{"id": "o-1", "name": "Family", "key": "4.n8XP9bCpDSz9fBft9A7xhSJD7Nk5ysZMKqqGJAag5qlQmv6sZbgbowo0IaV5DgSEXc2lnYkIc1qOsGtoWQMOgxQDCGV2dYLEBjY7dRo88N2SQTVI8fZGVqDomHw7atlahndfGhJ2orb8PE16KIUVPJZreXiwHTbNuaL8b50gsrouWVpGnPW4BitzNO8oBvqqrGCJ9h98J8s7ao+mciZ/FRdLIIJ2j9iyNPnINDxgAHrpP45QkfUvb1nc6zOyDEWF0ST2g/eUsGBm2Az78Q5MooOyXJEWjNcyOnlWvCqipHRjcik0btaiJOYkNlDfZLnyNf1nhLx6N5QsrYOVppgWNQ==", "status": 2, "type": 2}]}, "folders": [{"id": "f-1", "name": "2.5xjYubTjZ01tvPfnQh+Dhg==|bO34zONJfsNnGikN9WzE9A==|lIxClPqn33wqP5Ab6tUMQvR0eDZ8O0uN9cu7QM/9L1c="}], "collections": [], "ciphers": [{"object": "cipherDetails", "id": "c-github", "type": 1, "organizationId": null, "folderId": "f-1", "key": null, "name": "2.+SrbfPv+WjFXRHJkRPKAvQ==|Mn4CsFaKkZpiWKt0oGFs1w==|b/UOBTJSP6+bihbRMsH3TpGm8Ykf35VNAop56/RcUmE=", "notes": "2.Be1lGYOw5NTT+/kBcCXl2w==|NAuxl3btGwqyk92NQC4Qn4gbzgAFd/hulWNVdVtcK30=|sbtgoH/jTNBVhiQDAVh+Li48pUaUvsXV1kwWWNdGwxM=", "favorite": false, "deletedDate": null, "fields": [{"name": "2.2DrWujd80IY2KE/srJF45g==|F6LpSkUq2rZFM0B0JazYWA==|AXs3aZ8w1kVcA1h60xhFCZf067nv59z52wXlFU7VU2w=", "value": "2.j0SzWITE5cXpiWp6YhV/Mw==|BA1umcdbLbtTImOeYtkgFA==|sDRgc8tcmfG5fDBIgxpy3FuyZq1dCaCY232HlpjMijo=", "type": 1}, {"name": "2.D3uU+Yft+9e5x43noTkxPw==|OXU4UpE5u5rQfj3HZMDHIw==|T5dWJ98cAprMZao2zdu2Uq/BnBZsbupXxtvkzs51JXk=", "value": "2.DGF93QzackMKPiWmRUTh5g==|ay9nVPvqw9J/Eso3HkBFSQ==|Mp7+dalYw+bU4ezT8AaB5NnO8ysF9Lsvb7DKad/RAIY=", "type": 0}], "login": {"username": "2.bhXLXrk7ba5D41bxqZIXUA==|ZblPsoxcITv7J6Kw0dqwpw==|+2C5y8eANg/Op0+oW/miOLCXVT8qYtTps1cCqMf4jgw=", "password": "2.kJNKxHomLZM5+az8eQm9XQ==|LGktKf4xwfH7mGic+XTUlg==|caOlJIrhhsnsIfju3Fh7vlCBhyYh0KZ0SxJGDKPiW4c=", "totp": "2.KszLFs+OY1rHCieIbB5XPw==|mdrIxR8oKihXhak6d8q66BNnvKQz/dLGRX7nCoE1Ne0zQSnHRK4vMY4rYmtWmEVMif1kpaFNdTnlsd9ve4p1KUkyVyoGuOa2Ex+Xpm/uaO8=|564Y8Lyz8XzVyiL5YJ7PLoaNQELGP+0MCVdebqLowo8=", "uris": [{"uri": "2.g9q1oS9posNrvobNBa7IBQ==|SiAp45iroeB6V+UkTUe/p4ZGxNYqsAPOLtYGmozDem4=|UO9oS+m5U7oWuvbvFPVjDIy1T0AKuERJyuN6A3S91J8=", "match": null}, {"uri": "2.JR450otom9vPb+tJftvUwg==|3ZLTysSK7G619MN+llYKQk8S3N1bBIsS8GA+yeOoLQw=|Bwt3myHL4fYxn/IymLWjmblxf2fbcgcLsfdp5bQ7c+s=", "match": null}]}, "secureNote": null, "card": null, "identity": null}, {"object": "cipherDetails", "id": "c-bank", "type": 1, "organizationId": "o-1", "folderId": null, "key": null, "name": "2.WHGHKpPnvtNsKiF1WjtSpQ==|Oql+Zy5hYjrRSRvb2N+oxQ==|vA4x/pRFTi8nF6erp+vsZn56ADI9Uv4QB7NW/Ytw5fw=", "notes": null, "favorite": false, "deletedDate": null, "fields": [], "login": {"username": "2.tpYMMbqhoMNJIyXSO27mqA==|EIhb3PjtSboa6dzt5O3Kow==|3Tj89nXOrM3owmSfkK7KLmozJpxgVBEK8KGLg4E5s1Y=", "password": "2.kebJF9YqY7cZIXnmyfsB+w==|8ZuNXbDgmWw/rrdNHeK3yA==|xqsCN9XSdkSzGMm5lZTXzxhHXjygFBALs+MJLRdRVMA=", "totp": null, "uris": [{"uri": "2.MkJWFHjG3w831QlY6dwP1A==|QHxppJIGywvDmB0YouYWGZ0HTTe23TFOlfq2ILHgUf0=|+9YAMP1YEmWADCc7SqhXraBtOA25mQkv8hDXYiDibMA=", "match": null}]}, "secureNote": null, "card": null, "identity": null}, {"object": "cipherDetails", "id": "c-itemkey", "type": 1, "organizationId": null, "folderId": null, "key": "2.WYxSpoJVSVNfhHqbBCpeqg==|a7SpufM43wg3XRsHCE+ccBMPXMUoUgAmtUQw+ogNBHXYt4ElkzoVBj5F1JhNBqmgLwPCvkQ80BihvS8nZw64FKcqok9c9I1rUXCBm14tilI=|akQue6pF++3Bj2lVXF8abVx3DV5MmK7lh8QkZraQQvg=", "name": "2.t4Gdgh98pOfTxmVMvuHr/A==|4Fhh5T/X2lVBOlEr1nfCcA==|N1GBXpl7lzLZqTNav3ddhlw9IPIu84mP/ZnOXNGdDXE=", "notes": null, "favorite": false, "deletedDate": null, "fields": [], "login": {"username": "2.QCR3Omdx8q5ZJzGBxqbwNA==|9w1SmjpWYXcXxps10SGXeUlGWUc5pQ5xAYSvIQyIKMI=|4pSNgVL60CcarVWN/SpOWzp5RSXrXBk72cRFZFQ81Og=", "password": "2.Ahz1EnzXlCnAhiOZsmdY9Q==|C7yf3OwFWuqWPhVXQtbJcw==|KA6UZUHcjClaUnYElh8LrAi3Wwc/s+xwFwFLlPe0SAU=", "totp": null, "uris": [{"uri": "2.YkOZPgs27f/+Imne5L/WtA==|FjLgkyAKGmz1qHxgeq7Zb+zD0aijaRkEtES2FlUqELE=|dmuKjkMkg5/yJqg9jHyaCn5XQ401tJ0dHh2qOUVlfaY=", "match": null}]}, "secureNote": null, "card": null, "identity": null}, {"object": "cipherDetails", "id": "c-deleted", "type": 1, "organizationId": null, "folderId": null, "key": null, "name": "2.7x12OW0TGM7YQ/tJGmh/cg==|Z7kbB8Fdr7SDaa7knBiqIw==|AcZlKnaU4IaqZb90DufPijYbHB+ZYvHz+yd2qX875u0=", "notes": null, "favorite": false, "deletedDate": "2026-01-01T00:00:00Z", "fields": [], "login": {"username": "2.btmFkcu23nBUeoePptoxDg==|IN1XTzmEv6OIgl5dM7ufUA==|StqCqfelR6sPp2jU+SKpspJZX0DybeMqHIcM+8YW33o=", "password": "2.nRufQVkgSbgXB7nKZShdHQ==|aaWH/wRle4G5ZBI+VgpQww==|EZ5aU2TpV+wzMxnJ+k1kgCmYpWB5PJe95mnghnkEWpo=", "totp": null, "uris": []}, "secureNote": null, "card": null, "identity": null}, {"object": "cipherDetails", "id": "c-card", "type": 3, "organizationId": null, "key": null, "name": "2.eQh9/ZKybU0Vy+Hl4nGPiw==|9S7AiZIf60sGoj1vLBlMAQ==|NuLuf4EAcy3joefEqxUOal/kLsqBhIEorEJZOQKdmns=", "notes": null, "deletedDate": null, "fields": [], "login": null, "secureNote": null, "identity": null, "card": {"cardholderName": "2.lPhYeyo6e26yS/HS5wyC+w==|6XWDfct+mWaawRklziz/XQ==|Oe4zS2kJISyxdJAbR2X/oXKHzJDTIUYdliMwSikBeGI=", "brand": "2.OJ7qYCkT/NSl885+evVD5Q==|mnRpvBt1W6BtmZggqJnxmg==|slbSbFfsqiBumYNvWIfFY8TrpVKwW6inBbCEEjObL8Y=", "number": "2.fWVRnxX0MkU2bsFXSmvVHg==|rdAooZiK81OChbR1nsp5xiWA3u7Mrq+UI8l2/NnDiJ8=|QMeF1m2iOKFvKC7vEpHszq67UE0lb4aDbkW8WaV3ix8=", "expMonth": "2.exl4Q+HHSSl+fG15iNdrzA==|qw+V6RI4kdR65PDD+Lqjtg==|fRkjtWC3Z1OALbE+xnVASWJPxr5I4yo3BJQE3D4czQ8=", "expYear": "2./O7rYaIRxOa9GOfZBE21dw==|j+Zg/sXiCFUrPJpNy2GQpw==|uauJTt9xE0VIMu2/Ub8RblN3sOJ6jkMc3UKg6PYhUC8=", "code": "2.Y+/yVCH3wypzKQqSQAiK1g==|lNpsmeJuVbCX+0vXVpq4dQ==|tY7RpnqrAVMYd6wiB7jV4OIJ6UT2KeLsOfWkpfBa2v4="}}, {"object": "cipherDetails", "id": "c-note", "type": 2, "organizationId": null, "key": null, "name": "2.ScsJFjqQ8VMep8eIswZREg==|Ep/LL/G3GLYjT56mfnfJ6A==|4NjLnfUolViPd0QzUhSssd8cuLBVtpiWVY0BKUGl/CQ=", "notes": "2.whb6FWGkWRu9s7nGZesT8A==|BO9xigh3fs/UfOqRJ3EFMxJRpw22HIBIRCACjvpT5Jk=|g8a3RIuYYxHgDyrh6U/pZoy8p3Ye4a707X/tCs7uzcM=", "deletedDate": null, "fields": [], "login": null, "secureNote": {"type": 0}, "card": null, "identity": null}, {"object": "cipherDetails", "id": "c-id", "type": 4, "organizationId": null, "key": null, "name": "2.sA5PoZap7G2d5SUuFljk0A==|KskpshLgx6vubNAVetsNLw==|/ahAxM/A4E8/ugormrHWqGanwBtwrla0M3gx7e3dsR4=", "notes": null, "deletedDate": null, "fields": [], "login": null, "secureNote": null, "card": null, "identity": {"firstName": "2.R9o1d8gkhLs14q7hDS9t8g==|zorDKUcnxkCJOf8mpS0Kjw==|r3RaKkCKktAbD5ZFM7Y/S/F3h3G3UPLA/yj6be8yQZg=", "lastName": "2.aryKdU7sf22fyZA+Mb559g==|T1D6VWlk9pgTETNdTT4ooA==|sg1cHW0HPHsxJx4jaujwJ1Vk8pDg6wQy/SImxwD36eE=", "email": "2.4nAUa7YzUUCfreSVKUoymA==|436cpic6aPFVKw7yJovq20YhOtZYaGNiUDAfxBQGPZM=|b7o4vs7Wkj921nrtyc+FWc6KsctOb+wW29E8cgV499E=", "city": "2.jpooHnOJXCFO/FlyfsXYog==|/KdE9KaQN5fuGft+GZaBuQ==|RWr30zANi0nlbpCEYh2VvBUj7W4SNFj6p1WZrcTaa8E=", "postalCode": "2.6PwDhBl299k0rMyA2y83nw==|Nmsa9xpE3Rvo6qSjZCV3RA==|9hKE6je/kPpUMHh6+UjdXJG50Rrzc/Oosglo8ghN8xg=", "passportNumber": "2.y16bvXsWPKVBwC9iAYVIfA==|0JV/TOQR6jQOb9AFwGy/sQ==|RTIUswOIFzcNuMVVfMy+GU7l4GBKehNWR5FkNNnrCEs="}}], "domains": null, "sends": []}, "userKeyB64": "z8Wg1AUBTujIg5qSS2u8HAR/migsYk9RGf9zu9ckxKPlsDgYub8MDFGUuJ/AT+GVKVjcD9uh6uBdoIiabHTBWw=="}"""
    }
}

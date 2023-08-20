package cinira.util

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.*


class EncryptionTest {
    private val privateKey = extractPrivateKey(unencryptedPrivateKeyPEM)
    private val publicKey = extractPublicKey(publicKeyPEM)
    private val decryptedPrivateKey = extractPrivateKey(encryptedPrivateKeyPEM, "^1GRK2&wlSRQSao*")

    @Test
    fun `aesEncrypt() from aesDecrypt()`() {
        val key = generateAESKey("f%UNLck19dtiiFvo")
        val encrypted = aesEncrypt(key, "This is only a test.".encodeToByteArray())
        assertThat(String(aesDecrypt(key, encrypted))).isEqualTo("This is only a test.")
    }

    @Test
    fun `aesDecrypt() value encrypted in Javascript`() {
        val key = generateAESKey("f%UNLck19dtiiFvo")
        val encrypted = Base64.getDecoder().decode("Xs9mgvm4R2cgbhPcDYmJYFrDZ4W1PyKmEmYIUTy7lLnrndYTFj602KatiI1P53TD")
        assertThat(String(aesDecrypt(key, encrypted))).isEqualTo("This is only a test.")
    }

    @Test
    fun `rsaDecrypt() from rsaEncrypt()`() {
        val encrypted = rsaEncrypt(publicKey, "This is only a test.".encodeToByteArray())
        assertThat(String(rsaDecrypt(decryptedPrivateKey, encrypted))).isEqualTo("This is only a test.")
        assertThat(String(rsaDecrypt(privateKey, encrypted))).isEqualTo("This is only a test.")
    }

    @Test
    fun `rsaDecrypt() value encrypted in Javascript`() {
        val encrypted = Base64.getDecoder()
            .decode("me7rAT0zexOCgRBGJXQXF04NybiNHPhbUmDTH2PTYs5FpaLIqasgB3ofWxSXx1X2Cy7R3yEuTycTLRfspW1N1WiSCPuK9lxU8L7XQAtUFJd5VpNDIMMFAfXyjPE/iOSLPgv4QVk29QXEtKpnKHFbXYL3Ur3eC7jGuSpVg25vtgZAG+ZMEVWk+xS13iCjej3zJnBAIAIGolSLOaFjuU6MaoVMb6HEK0kjyNTUuueNewCyfgCu2cT1Z6JE8lZ2lfX90lx88f6poOAntfg4wT1JzTWaSM0BHiz3FV4QUjf5NNH6JSqaC5MTV6DgtmtAYrQ6iW2xtV/e05YqpB5wE7wz0Q==")
        assertThat(String(rsaDecrypt(decryptedPrivateKey, encrypted))).isEqualTo("This is only a test.")
        assertThat(String(rsaDecrypt(privateKey, encrypted))).isEqualTo("This is only a test.")
    }

    companion object {

        /* Encrypted private key. */
        val encryptedPrivateKeyPEM = """
            -----BEGIN ENCRYPTED PRIVATE KEY-----
            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
            -----END ENCRYPTED PRIVATE KEY-----
        """.trimIndent()

        /* Public key corresponding to [un]encryptedPrivateKeyPEM. */
        val publicKeyPEM = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyf4KnwPbZ5NNN0qxBj+5
            VSr2g1D/go/yh1YNGWZ/bgva9yNknyACKrcXUORbaq00R1s9Cw2IK7w9VkT775xW
            qJ/midxfYMcZ/SYcXsNMqHvrMQdR6o3Mi0FbvKFb3V9ar7+6ZzSa3wKlN9vCy6Zs
            AQuMEI/LlV1RrUjQ7kORSnJz16Q2m9A8UFgzNxGCUBBEXOzZoBVnNMdE7Yi0VwDQ
            /zk8hQwUPu9iykFmcFSRg8fHStx5zRS2xRhUdEVJnXGP7CRrZRqQiA/F/2TK/35X
            gNfOv+iauxEsfirKOvleTzWQsVil5gesaYtOqRVYyZptVn1hwgUF/Yf53i586WbN
            0wIDAQAB
            -----END PUBLIC KEY-----
        """.trimIndent()

        /* Same private key as encryptedPrivateKeyPEM but with encryption removed. */
        val unencryptedPrivateKeyPEM = """
            -----BEGIN PRIVATE KEY-----
            MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJ/gqfA9tnk003
            SrEGP7lVKvaDUP+Cj/KHVg0ZZn9uC9r3I2SfIAIqtxdQ5FtqrTRHWz0LDYgrvD1W
            RPvvnFaon+aJ3F9gxxn9Jhxew0yoe+sxB1HqjcyLQVu8oVvdX1qvv7pnNJrfAqU3
            28LLpmwBC4wQj8uVXVGtSNDuQ5FKcnPXpDab0DxQWDM3EYJQEERc7NmgFWc0x0Tt
            iLRXAND/OTyFDBQ+72LKQWZwVJGDx8dK3HnNFLbFGFR0RUmdcY/sJGtlGpCID8X/
            ZMr/fleA186/6Jq7ESx+Kso6+V5PNZCxWKXmB6xpi06pFVjJmm1WfWHCBQX9h/ne
            LnzpZs3TAgMBAAECggEAKSCwyO/gHJbBgiCTKtKOyeiViOdVHyBwIV5EDIfyKlX/
            n5J1SnEZ/9iHxtC4TGA35M+O/lEjCMSrOIWTRpZujqcAKdHVGb9wazr3S9Q4J5YT
            rUfwRfHZVAFazG2OZuSjcmV3bswnPIEtYtI8N3sLQqs3OagNq7v0hXPuFpVrX9zR
            GWRpoe0uIM/KbIO9IQ5dCZqdUHuIhdGEKQpUSxz0YuCnb8ieR0BRxhtrkP8WRq1N
            cOQrDQj08oc4vEJBkfVQyibZZDQYW4VyS+6fWMs8Aziot/mF0x6kpH00v7jABxrx
            0smS9kbq9OBOnAJ7wNCIjPVyvSQc3qN3bclhy87zAQKBgQD1h4G8/KAp2CkRT9mI
            jftn7uoj2bPexOxba4IyJNWA2NGffX1zEeyIuG7OrWVasgABOify5BjnegqvZF2c
            //zfNHfaBelRAKrnUmDcalMvTc18p7pBEwm1kVWWqtqfNnODac/dXJVZJrAJRdFN
            JwgA4qEhdPj0KY7kWBUHewWG5QKBgQDSmzuWWpsyvPtZOdMcC4ey1okF++2jbEk5
            a6WP544pehtKc0wOwtTxRl2cbz0KgedPnZD/hSWEe6AnJN+8MFraeTc+SDgRL6Wt
            1/iqS+kR0kKSPFvSWpdG+urRZYBc38LNK2H/LXpISp8Khe5BmIOCmfYKiMWVxAFB
            ZO7M0Ei+VwKBgQC9ufJE6SmSbBh/6iX8YUqN644+GbHmSGEj25WFzfS1VdXV2pCf
            5I/Urj/hsReK19UtHZVVGXEtHZ84HORBt4XdrJuYe8zo7Q0jJwL2D6sr+ID6/Fju
            hBmSljV+8ZNySA9G0vLu6OX3N+/7mlm7tpd2p6k/QzZE5gAm7vGBEE0bCQKBgBQx
            pkkIbxEyZbdsf/2UbXKMd58HRQYCgBLta3ac8ViwyKUe4RAZRmnMIXW6hNPZGODd
            buXRUoOdhwG522okCNIiBVYHfrjHJM/CgalyleqLiq6S8wr8fLzlmlZxsRk2q2sY
            2dCp/6um3BEaPnozsYh4Uss3yhpOLQCkOPGSlycJAoGAZJ7YOk7cdh/Yad27OEyo
            +dDlV+b4koRA6zzU2uAh2vlYuE1npvGrsaL6qTeqqoDTRUfBcpHYQv7nFar6Y15a
            nxZcexrQDzApt9GKNW/rGWGTV8v3sRtO5BJRNVxggoRRnwe9W7wIP6uQBSFyM/AJ
            Ao2RiE/K/t0AF6P3meiWc84=
            -----END PRIVATE KEY-----
        """.trimIndent()
    }
}
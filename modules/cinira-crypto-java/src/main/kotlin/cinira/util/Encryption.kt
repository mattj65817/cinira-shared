package cinira.util

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.Cipher.ENCRYPT_MODE
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * Extract a section from a PEM file. Returns a pair consisting of the section name (header text minus the `-----BEGIN`
 * prefix and the `-----` suffix) and the section content *not* including the header and footer (`-----END...`) lines.
 *
 * @param pem the PEM file content.
 * @param name the name of the section to extract, typically `PUBLIC KEY` or `PRIVATE KEY`.
 */
private fun extractSection(pem: String, name: String): Pair<String, List<String>> {
    val lines = pem.split(newline)
    val beginIndex = lines.indexOfFirst { line ->
        line.startsWith("-----BEGIN ") && line.endsWith(" ${name}-----")
    }
    if (-1 == beginIndex) {
        throw IllegalStateException("Section [$name] not found in PEM content.")
    }
    val line = lines[beginIndex]
    val header = line.substring(11, line.length - 5)
    return header to lines.subList(beginIndex + 1, lines.indexOf("-----END ${header}-----"))
}

/**
 * Decrypt an OpenSSL private key in PBKDF2/HMAC/SHA-256/AES-256-CBC format. This is the format produced by
 *
 * ```shell
 * $ openssl genpkey -aes-256-cbc -algorithm rsa -out private-key.pem -pass stdin -pkeyopt rsa_keygen_bits:2048
 * ```
 *
 * @param data the encrypted private key data.
 * @param passphrase the encryption passphrase.
 */
private fun decryptPrivateKey(data: ByteArray, passphrase: String) =
    KeyFactory.getInstance("RSA").let { keyFactory ->

        /* Parse the encrypted key bag. Verify that the algorithm IDs are as expected/supported. */
        val bag = ASN1Contents.fromBytes(data)
        if (!bag.oids[0].contentEquals(ALGORITHM_IDS.PBKDF2)
            || !bag.oids[1].contentEquals(ALGORITHM_IDS.PKCS5_PBES2)
            || !bag.oids[2].contentEquals(ALGORITHM_IDS.HMAC_WITH_SHA256)
            || !bag.oids[3].contentEquals(ALGORITHM_IDS.AES_256_CBC)
        ) {
            throw IllegalStateException("Unexpected algorithm ID(s) in encrypted private key bag.")
        }

        /* Extract the encryption parameters and encrypted private key data. */
        val salt = bag.strings[0]
        val iterations = bag.numbers[0]
        val iv = bag.strings[1]
        val encryptedKey = bag.strings[2]

        /* Decrypt and return the private key. */
        val pbeParams = PBEParameterSpec(salt, iterations, IvParameterSpec(iv))
        val pbeKeySpec = PBEKeySpec(passphrase.toCharArray())
        val passphraseKey = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256")
            .generateSecret(pbeKeySpec)
        Cipher.getInstance("PBEWithHmacSHA256AndAES_256").let { cipher ->
            cipher.init(DECRYPT_MODE, passphraseKey, pbeParams)
            keyFactory.generatePrivate(PKCS8EncodedKeySpec(cipher.doFinal(encryptedKey)))!!
        }
    }

/**
 * Decrypt a block of AES-encrypted data as produced by [aesEncrypt()]. The first 16 bytes of the `ivAndEncrypted`
 * buffer must be the initialization vector.
 *
 * @param key the AES-CBC-256 key, typically generated via {@link generateAESKey()}.
 * @param ivAndEncrypted the initialization vector (16 bytes) and encrypted data.
 */
fun aesDecrypt(key: SecretKey, ivAndEncrypted: ByteArray) =
    Cipher.getInstance("AES/CBC/PKCS5Padding").let { cipher ->
        val iv = ivAndEncrypted.sliceArray(0 until 16)
        val encrypted = ivAndEncrypted.sliceArray(16 until ivAndEncrypted.size)
        cipher.init(DECRYPT_MODE, SecretKeySpec(key.encoded, "AES"), IvParameterSpec(iv))
        cipher.doFinal(encrypted)!!
    }

/**
 * AES-encrypt a block of data. Generates a random initialization vector, which is included in the returned encrypted
 * data buffer as its first 16 bytes.
 *
 * @param key the AES-CBC-256 key, typically generated via {@link generateAESKey()}.
 * @param data the data to encrypt.
 */
fun aesEncrypt(key: SecretKey, data: ByteArray) =
    Cipher.getInstance("AES/CBC/PKCS5Padding").let { cipher ->
        val iv = ByteArray(16)
        SecureRandom.getInstanceStrong().nextBytes(iv)
        cipher.init(ENCRYPT_MODE, SecretKeySpec(key.encoded, "AES"), IvParameterSpec(iv))
        iv + cipher.doFinal(data)
    }

/**
 * Generate an AES key by PBKDF2-stretching a passphrase with a given (or default) salt. The key can be used with
 * {@link aesDecrypt()} and {@link aesEncrypt()} to symmetrically encrypt and decrypt arbitrary data.
 *
 * @param passphrase the passphrase.
 * @param salt the salt to use when stretching the passphrase into a key, if not provided, the SHA-256 hash of the
 * passphrase is used.
 */
fun generateAESKey(passphrase: String, salt: ByteArray? = null) =
    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").let { factory ->
        val encodedPassphrase = passphrase.encodeToByteArray()
        val saltValue = if (null != salt) {
            if (16 != salt.size) {
                throw IllegalArgumentException("Salt must be exactly 16 bytes in length.")
            }
            salt
        } else {
            MessageDigest.getInstance("SHA-256")
                .digest(encodedPassphrase)
                .sliceArray(0 until 16)
        }
        factory.generateSecret(PBEKeySpec(passphrase.toCharArray(), saltValue, 2048, 256))!!
    }


/**
 * Decrypt a block of RSA-encrypted data as produced by [rsaEncrypt()].
 *
 * @param privateKey the private key with which to decrypt.
 * @param encrypted the encrypted data to decrypt.
 */
fun rsaDecrypt(privateKey: PrivateKey, encrypted: ByteArray) =
    Cipher.getInstance("RSA/ECB/OAEPPADDING").let { cipher ->
        cipher.init(DECRYPT_MODE, privateKey, oaepParams)
        cipher.doFinal(encrypted)!!
    }

/**
 * RSA-encrypt a block of data.
 *
 * @param publicKey the public key with which to encrypt.
 * @param data the data to encrypt.
 */
fun rsaEncrypt(publicKey: PublicKey, data: ByteArray) =
    Cipher.getInstance("RSA/ECB/OAEPPADDING").let { cipher ->
        cipher.init(ENCRYPT_MODE, publicKey, oaepParams)
        cipher.doFinal(data)!!
    }

/**
 * Extract the private key from a PEM file, optionally decrypting it using a given `passphrase` if it is encrypted.
 *
 * @param pem the PEM file content.
 * @param passphrase the encryption passphrase, if the key is encrypted.
 */
fun extractPrivateKey(pem: String, passphrase: String? = null) =
    KeyFactory.getInstance("RSA").let { factory ->
        val (header, lines) = extractSection(pem, "PRIVATE KEY")
        val decoded = base64Decoder.decode(lines.joinToString(""))
        if (!header.startsWith("ENCRYPTED ")) {
            factory.generatePrivate(PKCS8EncodedKeySpec(decoded))!!
        } else if (null == passphrase) {
            throw IllegalArgumentException("Passphrase required for encrypted private key.");
        } else {
            decryptPrivateKey(decoded, passphrase)
        }
    }

/**
 * Extract the public key from a PEM file.
 *
 * @param pem the PEM file content.
 */
fun extractPublicKey(pem: String) =
    KeyFactory.getInstance("RSA").let { factory ->
        val (_, lines) = extractSection(pem, "PUBLIC KEY")
        factory.generatePublic(X509EncodedKeySpec(base64Decoder.decode(lines.joinToString(""))))!!
    }

/**
 * Base64 decoder.
 */
private val base64Decoder = Base64.getDecoder()

/**
 * Hex decoder.
 */
private val hexDecoder = HexFormat.of()

/**
 * Pattern used to split on `\n` or `\r\n`.
 */
private val newline = Regex("\r?\n")

/**
 * RSA-OAEP decryption parameters.
 */
private val oaepParams = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT)

/**
 * Expected algorithm IDs for encrypted private keys.
 */
private val ALGORITHM_IDS = object {
    val AES_256_CBC = hexDecoder.parseHex("60864801650304012A")
    val HMAC_WITH_SHA256 = hexDecoder.parseHex("2A864886F70D0209")
    val PBKDF2 = hexDecoder.parseHex("2A864886F70D01050D")
    val PKCS5_PBES2 = hexDecoder.parseHex("2A864886F70D01050C")
    val RSA_ENCRYPTION = hexDecoder.parseHex("2A864886F70D010101")
}
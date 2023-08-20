import crypto from 'crypto';
import { freeze } from 'immer';
import { ASN1Contents } from './ASN1Contents';

/**
 * AES-CBC-256 algorithm parameters.
 */
const AES_CBC_256_ALGORITHM_PARAMS = freeze({
  name: 'AES-CBC',
  length: 256,
});

/**
 * Expected algorithm IDs for encrypted private keys.
 */
const ALGORITHM_IDS = freeze({
  AES_256_CBC: Buffer.of(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a),
  HMAC_WITH_SHA256: Buffer.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09),
  PBKDF2: Buffer.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d),
  PKCS5_PBES2: Buffer.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c),
  RSA_ENCRYPTION: Buffer.of(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01),
});

/**
 * PBKDF2 with SHA-256 hash algorithm (base) parameters.
 */
const PBKDF2_ALGORITHM_PARAMS = freeze({
  name: 'PBKDF2',
  hash: 'SHA-256',
});

/**
 * RSA-OAEP algorithm parameters.
 */
const RSA_OAEP_ALGORITHM_PARAMS = freeze({
  hash: 'SHA-256',
  name: 'RSA-OAEP',
});

/**
 * UTF-8 text encoder.
 */
const utf8Encoder = new TextEncoder();

/**
 * Pattern used to split on `\n` or `\r\n`.
 */
const newline = /\r?\n/g;

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
async function decryptPrivateKey(data: Buffer, passphrase: string) {
  /* Parse the encrypted key bag. Verify that the algorithm IDs are as expected/supported. */
  const bagContents = ASN1Contents.fromBuffer(data);
  if (
    !bagContents.oids[0].equals(ALGORITHM_IDS.PBKDF2) ||
    !bagContents.oids[1].equals(ALGORITHM_IDS.PKCS5_PBES2) ||
    !bagContents.oids[2].equals(ALGORITHM_IDS.HMAC_WITH_SHA256) ||
    !bagContents.oids[3].equals(ALGORITHM_IDS.AES_256_CBC)
  ) {
    throw Error('Unexpected algorithm ID(s) in encrypted private key bag.');
  }

  /* Extract the encryption parameters and encrypted private key data. */
  const salt = bagContents.strings[0];
  const iterations = bagContents.numbers[0];
  const iv = bagContents.strings[1];
  const encryptedKey = bagContents.strings[2];

  /* Stretch the passphrase into the decryption key and decrypt the private key. */
  const passphraseKey = await crypto.subtle.importKey('raw', utf8Encoder.encode(passphrase), 'PBKDF2', false, [
    'deriveBits',
    'deriveKey',
  ]);
  const decryptionKey = await crypto.subtle.deriveKey(
    {
      ...PBKDF2_ALGORITHM_PARAMS,
      iterations,
      salt,
    },
    passphraseKey,
    AES_CBC_256_ALGORITHM_PARAMS,
    true,
    ['decrypt', 'encrypt'],
  );
  const privateKeyData = await crypto.subtle.decrypt(
    {
      ...AES_CBC_256_ALGORITHM_PARAMS,
      iv,
    },
    decryptionKey,
    encryptedKey,
  );
  const keyContents = ASN1Contents.fromBuffer(Buffer.from(privateKeyData));
  if (!keyContents.oids[0].equals(ALGORITHM_IDS.RSA_ENCRYPTION)) {
    throw Error('Unexpected algorithm ID in encrypted private key.');
  }
  return crypto.subtle.importKey('pkcs8', privateKeyData, RSA_OAEP_ALGORITHM_PARAMS, true, ['decrypt']);
}

/**
 * Extract a section from a PEM file. Returns a pair consisting of the section name (header text minus the `-----BEGIN`
 * prefix and the `-----` suffix) and the section content *not* including the header and footer (`-----END...`) lines.
 *
 * @param pem the PEM file content.
 * @param name the name of the section to extract, typically `PUBLIC KEY` or `PRIVATE KEY`.
 */
function extractSection(pem: string, name: string) {
  const lines = pem.split(newline);
  const beginIndex = lines.findIndex((line) => line.startsWith('-----BEGIN ') && line.endsWith(` ${name}-----`));
  if (-1 === beginIndex) {
    throw Error(`Section [${name}] not found in PEM content.`);
  }
  const line = lines[beginIndex];
  const header = line.substring(11, line.length - 5);
  return [header, lines.slice(beginIndex + 1, lines.indexOf(`-----END ${header}-----`))] as const;
}

/**
 * Generate an AES key by PBKDF2-stretching a passphrase with a given (or default) salt. The key can be used with
 * {@link aesDecrypt()} and {@link aesEncrypt()} to symmetrically encrypt and decrypt arbitrary data.
 *
 * @param passphrase the passphrase.
 * @param salt the salt to use when stretching the passphrase into a key, if not provided, the first 16 bytes of the
 * SHA-256 hash of the passphrase is used.
 */
export async function generateAESKey(passphrase: string, salt?: Buffer) {
  const encodedPassphrase = utf8Encoder.encode(passphrase);
  let saltValue: Buffer;
  if (null != salt) {
    if (16 !== salt.length) {
      throw Error('Salt must be exactly 16 bytes in length.');
    }
    saltValue = salt;
  } else {
    saltValue = crypto.createHash('SHA-256').update(encodedPassphrase).digest().subarray(0, 16);
  }
  const passphraseKey = await crypto.subtle.importKey('raw', encodedPassphrase, PBKDF2_ALGORITHM_PARAMS, false, [
    'deriveBits',
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      ...PBKDF2_ALGORITHM_PARAMS,
      iterations: 2048,
      salt: saltValue,
    },
    passphraseKey,
    AES_CBC_256_ALGORITHM_PARAMS,
    true,
    ['decrypt', 'encrypt'],
  );
}

/**
 * Decrypt a block of AES-encrypted data as produced by [aesEncrypt()]. The first 16 bytes of the `ivAndEncrypted`
 * buffer must be the initialization vector.
 *
 * @param key the AES-CBC-256 key, typically generated via {@link generateAESKey()}.
 * @param ivAndEncrypted the initialization vector (16 bytes) and encrypted data.
 */
export async function aesDecrypt(key: CryptoKey, ivAndEncrypted: Buffer) {
  const iv = ivAndEncrypted.subarray(0, 16);
  const encrypted = ivAndEncrypted.subarray(16);
  return Buffer.from(
    await crypto.subtle.decrypt(
      {
        ...AES_CBC_256_ALGORITHM_PARAMS,
        iv,
      },
      key,
      encrypted,
    ),
  );
}

/**
 * AES-encrypt a block of data. Generates a random initialization vector, which is included in the returned encrypted
 * data buffer as its first 16 bytes.
 *
 * @param key the AES-CBC-256 key, typically generated via {@link generateAESKey()}.
 * @param data the data to encrypt.
 */
export async function aesEncrypt(key: CryptoKey, data: Buffer) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const encrypted = Buffer.from(
    await crypto.subtle.encrypt(
      {
        ...AES_CBC_256_ALGORITHM_PARAMS,
        iv,
      },
      key,
      data,
    ),
  );
  return Buffer.concat([iv, encrypted]);
}

/**
 * Decrypt a block of RSA-encrypted data as produced by [rsaEncrypt()].
 *
 * @param privateKey the private key with which to decrypt.
 * @param encrypted the encrypted data to decrypt.
 */
export async function rsaDecrypt(privateKey: CryptoKey, encrypted: Buffer) {
  return Buffer.from(await crypto.subtle.decrypt(RSA_OAEP_ALGORITHM_PARAMS, privateKey, encrypted));
}

/**
 * RSA-encrypt a block of data.
 *
 * @param publicKey the public key with which to encrypt.
 * @param data the data to encrypt.
 */
export async function rsaEncrypt(publicKey: CryptoKey, data: Buffer) {
  return Buffer.from(await crypto.subtle.encrypt(RSA_OAEP_ALGORITHM_PARAMS, publicKey, data));
}

/**
 * Extract the private key from a PEM file, optionally decrypting it using a given `passphrase` if it is encrypted.
 *
 * @param pem the PEM file content.
 * @param passphrase the encryption passphrase, if the key is encrypted.
 */
export async function extractPrivateKey(pem: string, passphrase?: string) {
  const [header, lines] = extractSection(pem, 'PRIVATE KEY');
  const data = Buffer.from(lines.join(''), 'base64');
  if (!header.startsWith('ENCRYPTED ')) {
    return crypto.subtle.importKey('pkcs8', data, RSA_OAEP_ALGORITHM_PARAMS, true, ['decrypt']);
  } else if (null == passphrase) {
    throw Error('Passphrase required for encrypted private key.');
  } else {
    return decryptPrivateKey(data, passphrase!);
  }
}

/**
 * Extract the public key from a PEM file.
 *
 * @param pem the PEM file content.
 */
export async function extractPublicKey(pem: string) {
  const [, lines] = extractSection(pem, 'PUBLIC KEY');
  const data = Buffer.from(lines.join(''), 'base64');
  return crypto.subtle.importKey('spki', data, RSA_OAEP_ALGORITHM_PARAMS, true, ['encrypt']);
}

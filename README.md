# webservco/encryption

A PHP component/library. Please see [webservco/sandbox](https://webservco.github.io/sandbox/) for an example project using these types of components.

Encrypts secrets for storage with a key from the configuration (XChaCha20-Poly1305, libsodium), each bound to its row by associated data.

- Requires: PHP extension `sodium`; a configuration key that holds the encryption key
- Related: `webservco/configuration` (the factory reads the key); `webservco/mfa` (stores its TOTP secrets in this format)

---

## Installation

```shell
composer require webservco/encryption
```

---

## Usage

```php
use WebServCo\Encryption\Factory\SecretEncryptionServiceFactory;

// \WebServCo\Encryption\Contract\SecretEncryptionServiceFactoryInterface
$factory = new SecretEncryptionServiceFactory(
    $configurationGetter, // \WebServCo\Configuration\Contract\ConfigurationGetterInterface
);
// \WebServCo\Encryption\Contract\SecretEncryptionServiceInterface
$encryptionService = $factory->createSecretEncryptionService('EXAMPLE_ENCRYPTION_KEY');

// The associated data names the row and the column. It isn't secret and isn't stored: build it again to decrypt.
$associatedData = sprintf('account_token|secret|%s', $accountId);
$storedValue = $encryptionService->encrypt($secret, $associatedData);
$secret = $encryptionService->decrypt($storedValue, $associatedData);
```

Without the configuration, `new SodiumSecretEncryptionService($key)` takes the key itself, 32 raw bytes.

---

## Contracts

| Interface | Implementation | Purpose |
| --- | --- | --- |
| `Contract\SecretEncryptionServiceFactoryInterface` | `Factory\SecretEncryptionServiceFactory` | Creates `SecretEncryptionServiceInterface` with the key a configuration key holds. |
| `Contract\SecretEncryptionServiceInterface` | `Service\SodiumSecretEncryptionService` | Encrypts a secret to base64 text, and decrypts it with the same associated data. |

Namespaces are relative to `WebServCo\Encryption\`.

---

## Configuration

The factory takes the name of the key, so each use can have its own.

```ini
[Encryption]

; Base64 of 32 random bytes; one key per application and environment:
; php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
EXAMPLE_ENCRYPTION_KEY = ''
```

---

## Notes

- **The key.** Keep it out of the database, and back it up: without it nothing decrypts. There is no key rotation: a new key makes every stored value unreadable.
- **Associated data.** Let it name the row and the column, as in the example: a value copied to another row, or swapped with another column, doesn't decrypt.
- **Size.** A stored value has 4 × ⌈(n + 41) / 3⌉ characters for n bytes of plaintext. A 40-byte token takes 108, and a `VARCHAR(255)` column holds up to 148 bytes.
- **Format.** A version byte (`\x01`), a 24-byte random nonce, then the ciphertext with its 16-byte tag, all in base64. The version byte is also part of the associated data. It is the format of `webservco/mfa` v0.0.2: the secrets it stored decrypt with the same key and associated data (a test pins it).
- **Random nonce.** The same secret encrypts to a different value each time, so a stored value can't be searched for or compared.
- **Errors.** `decrypt()` throws `UnexpectedValueException`: `Unknown ciphertext format.`, or `Unable to decrypt: wrong key, wrong data or changed ciphertext.` The factory: a missing key gives the configuration getter's own exception (`webservco/configuration`: `OutOfBoundsException`, `Configuration key "EXAMPLE_ENCRYPTION_KEY" does not exist.`), a key that isn't base64 `UnexpectedValueException` (`EXAMPLE_ENCRYPTION_KEY is not valid base64.`), a key of the wrong length `InvalidArgumentException` (`The encryption key must be 32 bytes long.`). No message contains the key or the secret.

---

## Development

```shell
# Start project.
ddev start
# Install dependencies.
ddev c u
# Run all validations.
ddev c c
# Run unit tests, with coverage (needs Xdebug, which DDEV leaves off).
ddev xdebug on && ddev c test:dox; ddev xdebug off
```

---

## License

[MIT](LICENSE.md)

<?php

declare(strict_types=1);

namespace WebServCo\Encryption\Contract;

interface SecretEncryptionServiceFactoryInterface
{
    /**
     * $keyName: the configuration key that holds the encryption key, base64 of 32 bytes.
     */
    public function createSecretEncryptionService(string $keyName): SecretEncryptionServiceInterface;
}

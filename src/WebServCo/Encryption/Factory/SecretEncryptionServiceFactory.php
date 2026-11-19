<?php

declare(strict_types=1);

namespace WebServCo\Encryption\Factory;

use Override;
use UnexpectedValueException;
use WebServCo\Configuration\Contract\ConfigurationGetterInterface;
use WebServCo\Encryption\Contract\SecretEncryptionServiceFactoryInterface;
use WebServCo\Encryption\Contract\SecretEncryptionServiceInterface;
use WebServCo\Encryption\Service\SodiumSecretEncryptionService;

use function base64_decode;
use function sprintf;

/**
 * Reads the key from the configuration: base64 of 32 bytes. Error messages never contain the key.
 */
final readonly class SecretEncryptionServiceFactory implements SecretEncryptionServiceFactoryInterface
{
    public function __construct(private ConfigurationGetterInterface $configurationGetter,)
    {
    }

    #[Override]
    public function createSecretEncryptionService(string $keyName): SecretEncryptionServiceInterface
    {
        return new SodiumSecretEncryptionService($this->getEncryptionKey($keyName));
    }

    private function getEncryptionKey(string $keyName): string
    {
        $key = base64_decode($this->configurationGetter->getString($keyName), true);

        if ($key === false) {
            throw new UnexpectedValueException(sprintf('%s is not valid base64.', $keyName));
        }

        return $key;
    }
}

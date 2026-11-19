<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Encryption\Factory;

use InvalidArgumentException;
use OutOfBoundsException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Throwable;
use UnexpectedValueException;
use WebServCo\Configuration\Contract\ConfigurationGetterInterface;
use WebServCo\Encryption\Factory\SecretEncryptionServiceFactory;
use WebServCo\Encryption\Service\SodiumSecretEncryptionService;

use function array_key_exists;
use function base64_encode;
use function random_bytes;
use function sprintf;

#[CoversClass(SecretEncryptionServiceFactory::class)]
#[UsesClass(SodiumSecretEncryptionService::class)]
final class SecretEncryptionServiceFactoryTest extends TestCase
{
    private const string ASSOCIATED_DATA = 'example|secret|42';
    private const string KEY_NAME = 'EXAMPLE_ENCRYPTION_KEY';
    private const string PLAINTEXT = 'example secret';

    public function testTheServiceUsesTheConfiguredKey(): void
    {
        $key = random_bytes(32);
        $ciphertext = $this->createFactory(base64_encode($key))
            ->createSecretEncryptionService(self::KEY_NAME)
            ->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA);

        self::assertSame(
            self::PLAINTEXT,
            (new SodiumSecretEncryptionService($key))->decrypt($ciphertext, self::ASSOCIATED_DATA),
        );
    }

    public function testAMissingKeyIsReported(): void
    {
        $exception = $this->catchException(null);

        self::assertInstanceOf(OutOfBoundsException::class, $exception);
        self::assertSame('Configuration key "EXAMPLE_ENCRYPTION_KEY" does not exist.', $exception->getMessage());
    }

    public function testAKeyThatIsNotBase64IsRejectedWithoutShowingIt(): void
    {
        $key = 'not base64!';
        $exception = $this->catchException($key);

        self::assertInstanceOf(UnexpectedValueException::class, $exception);
        self::assertSame('EXAMPLE_ENCRYPTION_KEY is not valid base64.', $exception->getMessage());
        self::assertStringNotContainsString($key, $exception->getMessage());
    }

    public function testAKeyOfTheWrongLengthIsRejectedWithoutShowingIt(): void
    {
        $key = base64_encode(random_bytes(16));
        $exception = $this->catchException($key);

        self::assertInstanceOf(InvalidArgumentException::class, $exception);
        self::assertSame('The encryption key must be 32 bytes long.', $exception->getMessage());
        self::assertStringNotContainsString($key, $exception->getMessage());
    }

    /**
     * @param ?string $encryptionKey null: the key is missing.
     */
    private function catchException(?string $encryptionKey): Throwable
    {
        try {
            $this->createFactory($encryptionKey)->createSecretEncryptionService(self::KEY_NAME);
        } catch (Throwable $throwable) {
            return $throwable;
        }

        self::fail('The factory accepted an invalid key.');
    }

    /**
     * @param ?string $encryptionKey The configured value of KEY_NAME; null: the key is missing.
     */
    private function createFactory(?string $encryptionKey): SecretEncryptionServiceFactory
    {
        $configuration = [];

        if ($encryptionKey !== null) {
            $configuration[self::KEY_NAME] = $encryptionKey;
        }

        // Throws as `webservco/configuration` does for a missing key.
        $configurationGetter = self::createStub(ConfigurationGetterInterface::class);
        $configurationGetter->method('getString')->willReturnCallback(
            static function (string $key) use ($configuration): string {
                if (!array_key_exists($key, $configuration)) {
                    throw new OutOfBoundsException(sprintf('Configuration key "%s" does not exist.', $key));
                }

                return $configuration[$key];
            },
        );

        return new SecretEncryptionServiceFactory($configurationGetter);
    }
}

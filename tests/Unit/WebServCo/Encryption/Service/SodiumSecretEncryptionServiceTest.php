<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Encryption\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;
use WebServCo\Encryption\Service\SodiumSecretEncryptionService;

use function base64_decode;
use function base64_encode;
use function chr;
use function ord;
use function random_bytes;
use function str_repeat;
use function strlen;
use function substr;

#[CoversClass(SodiumSecretEncryptionService::class)]
final class SodiumSecretEncryptionServiceTest extends TestCase
{
    private const string ASSOCIATED_DATA = 'admin|42';
    private const string PLAINTEXT = '12345678901234567890';

    /**
     * PLAINTEXT encrypted by `webservco/mfa` v0.0.2 with KNOWN_KEY and ASSOCIATED_DATA.
     */
    private const string KNOWN_CIPHERTEXT = 'AcQz+BzZIr8QwPAzAPEJyFQBehHpbcM/uLXnLZkFg0jN'
        . 'XJlblQguR/tLzwjoQ1cgk88Pt4B+kvDQ0dzn6w==';
    private const string KNOWN_KEY = 'test key: 32 bytes, never in use';

    public function testDecryptReturnsThePlaintext(): void
    {
        $service = $this->createService();

        self::assertSame(
            self::PLAINTEXT,
            $service->decrypt($service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA), self::ASSOCIATED_DATA),
        );
    }

    /**
     * Pins the stored format: what `webservco/mfa` v0.0.2 stored decrypts with the same key and associated data.
     */
    public function testAValueStoredByMfaDecrypts(): void
    {
        $service = new SodiumSecretEncryptionService(self::KNOWN_KEY);

        self::assertSame(self::PLAINTEXT, $service->decrypt(self::KNOWN_CIPHERTEXT, self::ASSOCIATED_DATA));
    }

    public function testEncryptingTwiceGivesDifferentCiphertexts(): void
    {
        $service = $this->createService();

        self::assertNotSame(
            $service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA),
            $service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA),
        );
    }

    public function testCiphertextDoesNotContainThePlaintext(): void
    {
        $decoded = $this->decode($this->createService()->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA));

        self::assertStringNotContainsString(self::PLAINTEXT, $decoded);
    }

    public function testChangedCiphertextIsRejected(): void
    {
        $service = $this->createService();
        $decoded = $this->decode($service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA));
        // Flip one bit in the encrypted part.
        $decoded[30] = chr(ord($decoded[30]) ^ 1);

        $this->expectException(UnexpectedValueException::class);

        $service->decrypt(base64_encode($decoded), self::ASSOCIATED_DATA);
    }

    public function testWrongKeyIsRejected(): void
    {
        $ciphertext = $this->createService()->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA);

        $this->expectException(UnexpectedValueException::class);

        $this->createService()->decrypt($ciphertext, self::ASSOCIATED_DATA);
    }

    public function testOtherAssociatedDataIsRejected(): void
    {
        $service = $this->createService();
        $ciphertext = $service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA);

        $this->expectException(UnexpectedValueException::class);

        $service->decrypt($ciphertext, 'admin|43');
    }

    #[DataProvider('unknownFormatProvider')]
    public function testUnknownFormatIsRejected(string $ciphertext): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageIs('Unknown ciphertext format.');

        $this->createService()->decrypt($ciphertext, self::ASSOCIATED_DATA);
    }

    public function testUnknownVersionIsRejected(): void
    {
        $service = $this->createService();
        $decoded = $this->decode($service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA));

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageIs('Unknown ciphertext format.');

        $service->decrypt(base64_encode("\x02" . substr($decoded, 1)), self::ASSOCIATED_DATA);
    }

    public function testKeyOfTheWrongLengthIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The encryption key must be 32 bytes long.');

        $service = new SodiumSecretEncryptionService(random_bytes(31));
        $service->encrypt(self::PLAINTEXT, self::ASSOCIATED_DATA);
    }

    /**
     * 4 × ⌈(n + 41) / 3⌉ characters for n bytes: version byte, nonce and tag (41 bytes), then base64.
     */
    #[DataProvider('sizeProvider')]
    public function testStoredValueHasTheExactSizeAndDecrypts(int $plaintextLength, int $storedLength): void
    {
        $service = $this->createService();
        $plaintext = str_repeat('a', $plaintextLength);
        $ciphertext = $service->encrypt($plaintext, self::ASSOCIATED_DATA);

        self::assertSame($storedLength, strlen($ciphertext));
        self::assertSame($plaintext, $service->decrypt($ciphertext, self::ASSOCIATED_DATA));
    }

    /**
     * @return array<string,array{0:int,1:int}>
     */
    public static function sizeProvider(): array
    {
        return [
            '000 bytes' => [0, 56],
            '001 byte' => [1, 56],
            '002 bytes' => [2, 60],
            '020 bytes, a TOTP secret' => [20, 84],
            '040 bytes, a token' => [40, 108],
            '148 bytes, the most a VARCHAR(255) holds' => [148, 252],
            '149 bytes' => [149, 256],
        ];
    }

    /**
     * @return array<string,array{0:string}>
     */
    public static function unknownFormatProvider(): array
    {
        return [
            'empty' => [''],
            'not base64' => ['not base64!'],
            'too short' => [base64_encode("\x01" . str_repeat('a', 39))],
        ];
    }

    private function decode(string $ciphertext): string
    {
        $decoded = base64_decode($ciphertext, true);

        if ($decoded === false) {
            self::fail('The ciphertext is not base64.');
        }

        return $decoded;
    }

    private function createService(): SodiumSecretEncryptionService
    {
        return new SodiumSecretEncryptionService(random_bytes(32));
    }
}

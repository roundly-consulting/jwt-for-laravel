<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

/**
 * Generates a 2048-bit RSA keypair for signing (private) and verifying (public)
 * RS256 user tokens. Refuses to overwrite existing keys without `--force`; the
 * private key is written with 0600 permissions.
 *
 * The keypair itself comes from crypto-for-laravel, so the generated key passes
 * exactly the guards the verifier applies (real RSA, ≥2048 bits, sane exponent).
 */
final class GenerateKeysCommand extends Command
{
    protected $signature = 'jwt:generate-keys {--force : Overwrite existing keys if present}';

    protected $description = 'Generate an RSA keypair for signing and verifying JWT user tokens';

    public function handle(): int
    {
        $privatePath = config('jwt.private_key_path');
        $publicPath = config('jwt.public_key_path');

        if (! is_string($privatePath) || $privatePath === '') {
            $this->components->error('Set JWT_PRIVATE_KEY_PATH before generating keys.');

            return self::FAILURE;
        }

        if (! is_string($publicPath) || $publicPath === '') {
            $this->components->error('Set JWT_PUBLIC_KEY_PATH before generating keys.');

            return self::FAILURE;
        }

        $force = (bool) $this->option('force');

        if (! $force && (file_exists($privatePath) || file_exists($publicPath))) {
            $this->components->error('JWT keys already exist. Re-run with --force to overwrite them.');

            return self::FAILURE;
        }

        try {
            $keypair = RsaKey::generate(2048);
            $privateKey = $keypair->privatePem();
            $publicKey = $keypair->publicPem();
        } catch (CryptoException $e) {
            $this->components->error("Failed to generate an RSA keypair: {$e->getMessage()}");

            return self::FAILURE;
        }

        File::ensureDirectoryExists(dirname($privatePath));
        File::ensureDirectoryExists(dirname($publicPath));

        // Lock the file down to 0600 BEFORE the key material lands in it, so
        // there is no window where the private key is umask-readable.
        if (! touch($privatePath) || ! chmod($privatePath, 0600)) {
            $this->components->error("Unable to create [{$privatePath}] with owner-only permissions.");

            return self::FAILURE;
        }

        if (file_put_contents($privatePath, $privateKey) === false) {
            $this->components->error("Unable to write the private key to [{$privatePath}].");

            return self::FAILURE;
        }

        if (file_put_contents($publicPath, $publicKey) === false) {
            $this->components->error("Unable to write the public key to [{$publicPath}].");

            return self::FAILURE;
        }

        $this->components->info("Wrote private key to [{$privatePath}] (0600).");
        $this->components->info("Wrote public key to [{$publicPath}].");
        $this->components->warn('Distribute the public key to verify-only services; keep the private key secret.');

        return self::SUCCESS;
    }
}

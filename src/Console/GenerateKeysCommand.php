<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

/**
 * Generates a 2048-bit RSA keypair for signing (private) and verifying (public)
 * RS256 user tokens. Refuses to overwrite existing keys without `--force`; the
 * private key is written with 0600 permissions.
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

        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            $this->components->error('Failed to generate an RSA keypair via OpenSSL.');

            return self::FAILURE;
        }

        $privateKey = '';

        if (openssl_pkey_export($resource, $privateKey) === false) {
            $this->components->error('Failed to export the generated private key.');

            return self::FAILURE;
        }

        $details = openssl_pkey_get_details($resource);

        if ($details === false || ! isset($details['key']) || ! is_string($details['key'])) {
            $this->components->error('Failed to extract the public key from the generated keypair.');

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

        if (file_put_contents($publicPath, $details['key']) === false) {
            $this->components->error("Unable to write the public key to [{$publicPath}].");

            return self::FAILURE;
        }

        $this->components->info("Wrote private key to [{$privatePath}] (0600).");
        $this->components->info("Wrote public key to [{$publicPath}].");
        $this->components->warn('Distribute the public key to verify-only services; keep the private key secret.');

        return self::SUCCESS;
    }
}

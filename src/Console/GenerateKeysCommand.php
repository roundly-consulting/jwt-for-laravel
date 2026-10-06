<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Console;

use Illuminate\Console\Command;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Jwt\Support\KeyPath;

/**
 * Generates a 2048-bit RSA keypair for signing (private) and verifying (public)
 * RS256 user tokens. Refuses to overwrite existing keys without `--force`.
 *
 * Both keys are staged in temp files next to their targets and renamed into
 * place only once both are written: the private key is owner-only (0600) from
 * its first byte, a failed run leaves an existing pair untouched, and a key that
 * is replaced becomes a new file, so a handle held on the old one never sees the
 * new key. Every filesystem failure ends in this command's own error and FAILURE.
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

        if (! is_string($privatePath) || trim($privatePath) === '') {
            $this->components->error('Set JWT_PRIVATE_KEY_PATH before generating keys.');

            return self::FAILURE;
        }

        if (! is_string($publicPath) || trim($publicPath) === '') {
            $this->components->error('Set JWT_PUBLIC_KEY_PATH before generating keys.');

            return self::FAILURE;
        }

        // Anchor relative paths to the application root, exactly as the
        // KeyRepository does when reading them — otherwise the keys land
        // wherever the command happened to be run from and the app can't
        // find them.
        $basePath = $this->laravel->basePath();
        $privatePath = KeyPath::resolve($privatePath, $basePath);
        $publicPath = KeyPath::resolve($publicPath, $basePath);

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

        foreach ([$privatePath, $publicPath] as $path) {
            $problem = $this->unwritable($path);

            if ($problem !== null) {
                $this->components->error($problem);

                return self::FAILURE;
            }
        }

        $privateTemp = $this->stage($privatePath, $privateKey, 0600);

        if ($privateTemp === null) {
            $this->components->error('Unable to create the private key at ['.$privatePath.']. Check that ['.dirname($privatePath).'] is writable.');

            return self::FAILURE;
        }

        $publicTemp = $this->stage($publicPath, $publicKey, 0644);

        if ($publicTemp === null) {
            @unlink($privateTemp);
            $this->components->error('Unable to create the public key at ['.$publicPath.']. Check that ['.dirname($publicPath).'] is writable. The existing keys are unchanged.');

            return self::FAILURE;
        }

        if (! @rename($privateTemp, $privatePath)) {
            @unlink($privateTemp);
            @unlink($publicTemp);
            $this->components->error("Unable to move the private key into place at [{$privatePath}]. The existing keys are unchanged.");

            return self::FAILURE;
        }

        if (! @rename($publicTemp, $publicPath)) {
            @unlink($publicTemp);
            $this->components->error("Wrote the private key, but could not move the public key into place at [{$publicPath}], so the pair no longer matches. Fix the permissions and re-run with --force.");

            return self::FAILURE;
        }

        $this->components->info("Wrote private key to [{$privatePath}] (0600).");
        $this->components->info("Wrote public key to [{$publicPath}].");
        $this->components->warn('Distribute the public key to verify-only services; keep the private key secret.');

        return self::SUCCESS;
    }

    /**
     * Why a key cannot be written to `$path`, or null when it may be. Checked for
     * both keys before anything is written, so a run that cannot finish changes
     * nothing. The filesystem calls are silenced and checked explicitly: under
     * Laravel their warnings would otherwise surface as a raw ErrorException.
     */
    private function unwritable(string $path): ?string
    {
        $directory = dirname($path);

        if (! is_dir($directory) && ! @mkdir($directory, 0755, true) && ! is_dir($directory)) {
            return "Unable to create the directory [{$directory}] for [{$path}].";
        }

        if (file_exists($path) && (! is_file($path) || ! is_writable($path))) {
            return "Unable to replace [{$path}]: it is not a writable file.";
        }

        return null;
    }

    /**
     * Writes `$contents` to a new temp file in `$path`'s own directory, so the
     * final rename() is atomic on one filesystem, and gives it `$mode`.
     * tempnam() creates the file 0600, so nothing else can read it while the key
     * lands. Null on any failure, with nothing left behind.
     */
    private function stage(string $path, #[\SensitiveParameter] string $contents, int $mode): ?string
    {
        $directory = dirname($path);
        $temp = @tempnam($directory, '.jwt-');

        if ($temp === false) {
            return null;
        }

        // tempnam() quietly falls back to the system temp directory when it
        // cannot use $directory; a key staged there would not move atomically.
        if (realpath(dirname($temp)) !== realpath($directory)
            || @file_put_contents($temp, $contents) !== strlen($contents)
            || ! @chmod($temp, $mode)) {
            @unlink($temp);

            return null;
        }

        return $temp;
    }
}

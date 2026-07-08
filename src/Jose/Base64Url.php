<?php

declare(strict_types=1);

namespace RoundlyConsulting\Jwt\Jose;

use RoundlyConsulting\Jwt\Jose\Exceptions\MalformedToken;

/**
 * Strict base64url (RFC 7515 §2, "Base64url Encoding") codec.
 *
 * Encoding produces the unpadded URL-safe alphabet; decoding restores padding
 * and rejects any input carrying standard-base64 characters (`+`, `/`, `=`) or
 * bytes outside the base64url alphabet, so a tampered segment never silently
 * decodes.
 */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * @throws MalformedToken when the input is not valid, unpadded base64url.
     */
    public static function decode(string $value): string
    {
        // Reject anything outside the base64url alphabet up front — including
        // the standard-base64 `+`, `/` and any stray `=` padding.
        if ($value === '' || preg_match('/[^A-Za-z0-9_-]/', $value) === 1) {
            throw new MalformedToken('Segment is not valid base64url.');
        }

        $remainder = strlen($value) % 4;

        if ($remainder === 1) {
            // 1 leftover char can never be a whole base64 group.
            throw new MalformedToken('Segment has an invalid base64url length.');
        }

        $padded = $remainder === 0
            ? $value
            : $value.str_repeat('=', 4 - $remainder);

        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);

        if ($decoded === false) {
            throw new MalformedToken('Segment could not be base64url-decoded.');
        }

        return $decoded;
    }
}

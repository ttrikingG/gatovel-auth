<?php

namespace nucleo\auth\mfa;

use InvalidArgumentException;

class Totp
{
    private const BASE32_ALPHABET =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    private const DEFAULT_PERIOD = 30;

    private const DEFAULT_DIGITS = 6;

    private const DEFAULT_WINDOW = 1;

    public static function generateSecret(
        int $bytes = 20
    ): string {
        if ($bytes < 16) {
            throw new InvalidArgumentException(
                'O segredo TOTP deve possuir pelo menos 16 bytes.'
            );
        }

        return self::base32Encode(
            random_bytes($bytes)
        );
    }

    public static function generateCode(
        string $secret,
        ?int $timestamp = null,
        int $period = self::DEFAULT_PERIOD,
        int $digits = self::DEFAULT_DIGITS
    ): string {
        self::validateConfiguration(
            $period,
            $digits
        );

        $secret = trim($secret);

        if ($secret === '') {
            throw new InvalidArgumentException(
                'O segredo TOTP não pode ser vazio.'
            );
        }

        $timestamp ??= time();

        $counter = intdiv(
            $timestamp,
            $period
        );

        $key = self::base32Decode(
            $secret
        );

        $binaryCounter = pack(
            'N*',
            0,
            $counter
        );

        $hash = hash_hmac(
            'sha1',
            $binaryCounter,
            $key,
            true
        );

        $offset = ord(
            $hash[
                strlen($hash) - 1
            ]
        ) & 0x0f;

        $binaryCode =
            ((ord($hash[$offset]) & 0x7f) << 24)
            | ((ord($hash[$offset + 1]) & 0xff) << 16)
            | ((ord($hash[$offset + 2]) & 0xff) << 8)
            | (ord($hash[$offset + 3]) & 0xff);

        $modulo = 10 ** $digits;

        $code = $binaryCode % $modulo;

        return str_pad(
            (string) $code,
            $digits,
            '0',
            STR_PAD_LEFT
        );
    }

    public static function verify(
        string $secret,
        string $code,
        ?int $timestamp = null,
        int $period = self::DEFAULT_PERIOD,
        int $digits = self::DEFAULT_DIGITS,
        int $window = self::DEFAULT_WINDOW
    ): bool {
        self::validateConfiguration(
            $period,
            $digits
        );

        if ($window < 0) {
            throw new InvalidArgumentException(
                'A janela de validação não pode ser negativa.'
            );
        }

        $code = trim($code);

        if (
            $code === ''
            || !ctype_digit($code)
            || strlen($code) !== $digits
        ) {
            return false;
        }

        $timestamp ??= time();

        for (
            $offset = -$window;
            $offset <= $window;
            $offset++
        ) {
            $comparisonTimestamp =
                $timestamp + ($offset * $period);

            $expectedCode = self::generateCode(
                $secret,
                $comparisonTimestamp,
                $period,
                $digits
            );

            if (
                hash_equals(
                    $expectedCode,
                    $code
                )
            ) {
                return true;
            }
        }

        return false;
    }

    public static function provisioningUri(
        string $issuer,
        string $account,
        string $secret
    ): string {
        $issuer = trim($issuer);
        $account = trim($account);
        $secret = trim($secret);

        if (
            $issuer === ''
            || $account === ''
            || $secret === ''
        ) {
            throw new InvalidArgumentException(
                'Issuer, conta e segredo são obrigatórios.'
            );
        }

        $label = $issuer . ':' . $account;

        $parameters = [
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => self::DEFAULT_DIGITS,
            'period' => self::DEFAULT_PERIOD,
        ];

        return 'otpauth://totp/'
            . rawurlencode($label)
            . '?'
            . http_build_query(
                $parameters,
                '',
                '&',
                PHP_QUERY_RFC3986
            );
    }

    private static function validateConfiguration(
        int $period,
        int $digits
    ): void {
        if ($period <= 0) {
            throw new InvalidArgumentException(
                'O período TOTP deve ser maior que zero.'
            );
        }

        if (
            $digits < 6
            || $digits > 8
        ) {
            throw new InvalidArgumentException(
                'A quantidade de dígitos TOTP deve estar entre 6 e 8.'
            );
        }
    }

    private static function base32Encode(
        string $data
    ): string {
        $binary = '';

        $buffer = 0;
        $bits = 0;

        $length = strlen($data);

        for ($i = 0; $i < $length; $i++) {
            $buffer =
                ($buffer << 8)
                | ord($data[$i]);

            $bits += 8;

            while ($bits >= 5) {
                $bits -= 5;

                $index =
                    ($buffer >> $bits)
                    & 0x1f;

                $binary .= self::BASE32_ALPHABET[$index];
            }
        }

        if ($bits > 0) {
            $index =
                ($buffer << (5 - $bits))
                & 0x1f;

            $binary .= self::BASE32_ALPHABET[$index];
        }

        return $binary;
    }

    private static function base32Decode(
        string $secret
    ): string {
        $secret = strtoupper(
            preg_replace(
                '/[\s=]+/',
                '',
                $secret
            ) ?? ''
        );

        if ($secret === '') {
            throw new InvalidArgumentException(
                'O segredo TOTP é inválido.'
            );
        }

        $buffer = 0;
        $bits = 0;
        $result = '';

        $length = strlen($secret);

        for ($i = 0; $i < $length; $i++) {
            $character = $secret[$i];

            $value = strpos(
                self::BASE32_ALPHABET,
                $character
            );

            if ($value === false) {
                throw new InvalidArgumentException(
                    'O segredo TOTP contém caracteres inválidos.'
                );
            }

            $buffer =
                ($buffer << 5)
                | $value;

            $bits += 5;

            if ($bits >= 8) {
                $bits -= 8;

                $result .= chr(
                    ($buffer >> $bits)
                    & 0xff
                );
            }
        }

        return $result;
    }
}
<?php

namespace nucleo\auth\verification;

use Gatovel\Database\Database;

class EmailVerificationToken
{
    private const TTL = 86400;

    public static function create(
        int $userId
    ): string {
        self::invalidateForUser(
            $userId
        );

        $token = bin2hex(
            random_bytes(32)
        );

        $tokenHash = hash(
            'sha256',
            $token
        );

        $expiresAt = date(
            'Y-m-d H:i:s',
            time() + self::TTL
        );

        Database::table(
            'email_verifications'
        )->insert(
            [
                'user_id' => $userId,
                'token_hash' => $tokenHash,
                'expires_at' => $expiresAt,
            ]
        );

        return $token;
    }

    public static function findUserId(
        string $token
    ): ?int {
        $tokenHash = hash(
            'sha256',
            $token
        );

        $verification = Database::table(
            'email_verifications'
        )
            ->where(
                'token_hash',
                $tokenHash
            )
            ->first();

        if ($verification === null) {
            return null;
        }

        if (
            $verification['used_at'] !== null
        ) {
            return null;
        }

        $expiresAt = \DateTimeImmutable::createFromFormat(
            'Y-m-d H:i:s',
            $verification['expires_at']
        );

        if ($expiresAt === false) {
            self::invalidate(
                (int) $verification['id']
            );

            return null;
        }

        $now = new \DateTimeImmutable();

        if ($expiresAt <= $now) {
            self::invalidate(
                (int) $verification['id']
            );

            return null;
        }

        return (int) $verification['user_id'];
    }

    public static function invalidate(
        int $id
    ): void {
        Database::table(
            'email_verifications'
        )
            ->where(
                'id',
                $id
            )
            ->update(
                [
                    'used_at' => date(
                        'Y-m-d H:i:s'
                    ),
                ]
            );
    }

    public static function invalidateForUser(
        int $userId
    ): void {
        $verifications = Database::table(
            'email_verifications'
        )
            ->where(
                'user_id',
                $userId
            )
            ->get();

        foreach ($verifications as $verification) {
            if (
                $verification['used_at'] !== null
            ) {
                continue;
            }

            self::invalidate(
                (int) $verification['id']
            );
        }
    }
}
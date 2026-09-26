<?php

namespace nucleo\auth\password;

use Gatovel\Database\Database;

class PasswordReset
{
    private const TTL = 3600;

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
            'password_resets'
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

        $reset = Database::table(
            'password_resets'
        )
            ->where(
                'token_hash',
                $tokenHash
            )
            ->first();

        if ($reset === null) {
            return null;
        }

        if (
            $reset['used_at'] !== null
        ) {
            return null;
        }

        $expiresAt = \DateTimeImmutable::createFromFormat(
            'Y-m-d H:i:s',
            $reset['expires_at']
        );

        if (
            $expiresAt === false
        ) {
            self::invalidate(
                (int) $reset['id']
            );

            return null;
        }

        $now = new \DateTimeImmutable();

        if (
            $expiresAt <= $now
        ) {
            self::invalidate(
                (int) $reset['id']
            );

            return null;
        }

        return (int) $reset['user_id'];
    }

    public static function invalidate(
        int $id
    ): void {
        Database::table(
            'password_resets'
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
        $resets = Database::table(
            'password_resets'
        )
            ->where(
                'user_id',
                $userId
            )
            ->get();

        foreach ($resets as $reset) {
            if (
                $reset['used_at'] !== null
            ) {
                continue;
            }

            self::invalidate(
                (int) $reset['id']
            );
        }
    }
}
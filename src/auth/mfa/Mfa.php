<?php

namespace nucleo\auth\mfa;

use Gatovel\Database\Database;
use InvalidArgumentException;
use nucleo\auth\contracts\MfaAuthenticatable;
use RuntimeException;

class Mfa
{
    public static function enable(
        MfaAuthenticatable $user,
        string $code
    ): bool {
        $userId = $user->getAuthIdentifier();

        if ($userId === null) {
            throw new InvalidArgumentException(
                'O usuário precisa possuir um identificador.'
            );
        }

        $mfa = self::findByUserId(
            $userId
        );

        if ($mfa === null) {
            throw new RuntimeException(
                'O MFA ainda não foi iniciado para este usuário.'
            );
        }

        if (
            !is_string($mfa['secret'] ?? null)
            || $mfa['secret'] === ''
        ) {
            throw new RuntimeException(
                'O segredo MFA não foi encontrado.'
            );
        }

        if (
            !Totp::verify(
                $mfa['secret'],
                $code
            )
        ) {
            return false;
        }

        $connection = Database::connection();

        $statement = $connection->prepare(
            'UPDATE user_mfa
             SET enabled = 1
             WHERE user_id = :user_id'
        );

        $statement->execute([
            'user_id' => $userId,
        ]);

        return true;
    }

    public static function disable(
        MfaAuthenticatable $user
    ): void {
        $userId = $user->getAuthIdentifier();

        if ($userId === null) {
            throw new InvalidArgumentException(
                'O usuário precisa possuir um identificador.'
            );
        }

        $connection = Database::connection();

        $statement = $connection->prepare(
            'UPDATE user_mfa
             SET enabled = 0
             WHERE user_id = :user_id'
        );

        $statement->execute([
            'user_id' => $userId,
        ]);
    }

    public static function isEnabled(
        MfaAuthenticatable $user
    ): bool {
        $userId = $user->getAuthIdentifier();

        if ($userId === null) {
            return false;
        }

        $mfa = self::findByUserId(
            $userId
        );

        if ($mfa === null) {
            return false;
        }

        return (bool) $mfa['enabled'];
    }

    public static function verify(
        MfaAuthenticatable $user,
        string $code
    ): bool {
        $userId = $user->getAuthIdentifier();

        if ($userId === null) {
            return false;
        }

        $mfa = self::findByUserId(
            $userId
        );

        if ($mfa === null) {
            return false;
        }

        if (!(bool) $mfa['enabled']) {
            return false;
        }

        if (
            !is_string($mfa['secret'] ?? null)
            || $mfa['secret'] === ''
        ) {
            return false;
        }

        return Totp::verify(
            $mfa['secret'],
            $code
        );
    }

    public static function setup(
        MfaAuthenticatable $user
    ): array {
        $userId = $user->getAuthIdentifier();

        if ($userId === null) {
            throw new InvalidArgumentException(
                'O usuário precisa possuir um identificador.'
            );
        }

        $existing = self::findByUserId(
            $userId
        );

        if ($existing !== null) {
            return [
                'secret' => $existing['secret'],
                'uri' => self::buildUri(
                    $user,
                    $existing['secret']
                ),
            ];
        }

        $secret = Totp::generateSecret();

        $connection = Database::connection();

        $statement = $connection->prepare(
            'INSERT INTO user_mfa
                (user_id, secret, enabled)
             VALUES
                (:user_id, :secret, 0)'
        );

        $statement->execute([
            'user_id' => $userId,
            'secret' => $secret,
        ]);

        return [
            'secret' => $secret,
            'uri' => self::buildUri(
                $user,
                $secret
            ),
        ];
    }

    public static function regenerate(
        MfaAuthenticatable $user
    ): array {
        $userId = $user->getAuthIdentifier();

        if ($userId === null) {
            throw new InvalidArgumentException(
                'O usuário precisa possuir um identificador.'
            );
        }

        $secret = Totp::generateSecret();

        $connection = Database::connection();

        $statement = $connection->prepare(
            'UPDATE user_mfa
             SET secret = :secret,
                 enabled = 0
             WHERE user_id = :user_id'
        );

        $statement->execute([
            'secret' => $secret,
            'user_id' => $userId,
        ]);

        if ($statement->rowCount() === 0) {
            $insert = $connection->prepare(
                'INSERT INTO user_mfa
                    (user_id, secret, enabled)
                 VALUES
                    (:user_id, :secret, 0)'
            );

            $insert->execute([
                'user_id' => $userId,
                'secret' => $secret,
            ]);
        }

        return [
            'secret' => $secret,
            'uri' => self::buildUri(
                $user,
                $secret
            ),
        ];
    }

    public static function getSecret(
        MfaAuthenticatable $user
    ): ?string {
        $userId = $user->getAuthIdentifier();

        if ($userId === null) {
            return null;
        }

        $mfa = self::findByUserId(
            $userId
        );

        if ($mfa === null) {
            return null;
        }

        return is_string($mfa['secret'] ?? null)
            ? $mfa['secret']
            : null;
    }

    private static function findByUserId(
        mixed $userId
    ): ?array {
        $connection = Database::connection();

        $statement = $connection->prepare(
            'SELECT *
             FROM user_mfa
             WHERE user_id = :user_id
             LIMIT 1'
        );

        $statement->execute([
            'user_id' => $userId,
        ]);

        $result = $statement->fetch();

        if ($result === false) {
            return null;
        }

        return $result;
    }

    private static function buildUri(
        MfaAuthenticatable $user,
        string $secret
    ): string {
        $email = $user->getAuthEmail();

        if (trim($email) === '') {
            throw new RuntimeException(
                'O usuário precisa possuir um e-mail para configurar o MFA.'
            );
        }

        return Totp::provisioningUri(
            'Gatovel Framework',
            $email,
            $secret
        );
    }
}
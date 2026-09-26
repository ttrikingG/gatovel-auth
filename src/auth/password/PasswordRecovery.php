<?php

namespace nucleo\auth\password;

use nucleo\auth\authentication\Password;
use nucleo\auth\contracts\UserRepository;

class PasswordRecovery
{
    private static ?UserRepository $repository = null;

    public static function setRepository(
        UserRepository $repository
    ): void {
        self::$repository = $repository;
    }

    public static function create(
        string $email
    ): ?string {
        if (self::$repository === null) {
            return null;
        }

        $email = trim(
            strtolower($email)
        );

        if ($email === '') {
            return null;
        }

        $user = self::$repository->findByEmail(
            $email
        );

        if ($user === null) {
            return null;
        }

        $identifier = $user->getAuthIdentifier();

        if (!is_int($identifier)) {
            return null;
        }

        return PasswordReset::create(
            $identifier
        );
    }

    public static function buildUrl(
        string $token
    ): string {
        return '/reset-password/'
            . urlencode($token);
    }

    public static function resetTokenIsValid(
        string $token
    ): bool {
        return PasswordReset::findUserId(
            $token
        ) !== null;
    }

    public static function reset(
        string $token,
        string $password
    ): bool {
        if (self::$repository === null) {
            return false;
        }

        $userId = PasswordReset::findUserId(
            $token
        );

        if ($userId === null) {
            return false;
        }

        if (strlen($password) < 8) {
            return false;
        }

        $user = self::$repository->find(
            $userId
        );

        if ($user === null) {
            return false;
        }

        if (!method_exists($user, 'save')) {
            return false;
        }

        $user->password = Password::hash(
            $password
        );

        if (!self::$repository->save($user)) {
            return false;
        }

        PasswordReset::invalidateForUser(
            $userId
        );

        return true;
    }
}

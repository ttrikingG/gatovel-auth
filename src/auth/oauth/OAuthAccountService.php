<?php

namespace nucleo\auth\oauth;

use nucleo\auth\contracts\Authenticatable;
use nucleo\auth\contracts\OAuthAccountRepository;
use nucleo\auth\contracts\UserRepository;
use nucleo\auth\oauth\exceptions\OAuthException;

class OAuthAccountService
{
    private static ?OAuthAccountRepository $accountRepository = null;

    private static ?UserRepository $userRepository = null;

    public static function setAccountRepository(
        OAuthAccountRepository $repository
    ): void {
        self::$accountRepository = $repository;
    }

    public static function setUserRepository(
        UserRepository $repository
    ): void {
        self::$userRepository = $repository;
    }

    public static function findUserId(
        string $provider,
        string $providerUserId
    ): ?int {
        if (
            self::$accountRepository === null
        ) {
            return null;
        }

        return self::$accountRepository->findUserId(
            $provider,
            $providerUserId
        );
    }

    public static function createAccount(
        int $userId,
        string $provider,
        string $providerUserId
    ): bool {
        if (
            self::$accountRepository === null
        ) {
            return false;
        }

        return self::$accountRepository->create(
            $userId,
            $provider,
            $providerUserId
        );
    }

    public static function findOrCreateUser(
        string $provider,
        array $oauthUser
    ): Authenticatable {
        if (
            self::$accountRepository === null
            || self::$userRepository === null
        ) {
            throw new OAuthException(
                'Os repositórios OAuth não foram configurados.'
            );
        }

        $providerUserId = $oauthUser['sub'] ?? null;

        if (
            !is_string($providerUserId)
            || trim($providerUserId) === ''
        ) {
            throw new OAuthException(
                'O provedor OAuth não retornou um identificador válido.'
            );
        }

        $existingUserId = self::findUserId(
            $provider,
            $providerUserId
        );

        if ($existingUserId !== null) {
            $user = self::$userRepository->find(
                $existingUserId
            );

            if ($user === null) {
                throw new OAuthException(
                    'A conta OAuth está vinculada a um usuário inexistente.'
                );
            }

            return $user;
        }

        $email = $oauthUser['email'] ?? null;

        if (
            !is_string($email)
            || trim($email) === ''
        ) {
            throw new OAuthException(
                'O provedor OAuth não retornou um e-mail válido.'
            );
        }

        $emailVerified = $oauthUser['email_verified'] ?? false;

        if ($emailVerified !== true) {
            throw new OAuthException(
                'O e-mail da conta OAuth não foi verificado.'
            );
        }

        $email = trim(
            strtolower($email)
        );

        $name = $oauthUser['name'] ?? $email;

        if (!is_string($name)) {
            $name = $email;
        }

        $existingUser = self::$userRepository->findByEmail(
            $email
        );

        if ($existingUser !== null) {
            $userId = $existingUser->getAuthIdentifier();

            if (!is_int($userId)) {
                throw new OAuthException(
                    'O identificador do usuário encontrado é inválido.'
                );
            }

            if (
                !self::createAccount(
                    $userId,
                    $provider,
                    $providerUserId
                )
            ) {
                throw new OAuthException(
                    'Não foi possível vincular a conta OAuth.'
                );
            }

            return $existingUser;
        }

        $user = self::$userRepository->create([
            'name' => $name,
            'email' => $email,
            'password' => null,
            'email_verified_at' => date(
                'Y-m-d H:i:s'
            ),
        ]);

        if ($user === null) {
            throw new OAuthException(
                'Não foi possível criar o usuário OAuth.'
            );
        }

        $userId = $user->getAuthIdentifier();

        if (!is_int($userId)) {
            throw new OAuthException(
                'O identificador do usuário criado é inválido.'
            );
        }

        if (
            !self::createAccount(
                $userId,
                $provider,
                $providerUserId
            )
        ) {
            throw new OAuthException(
                'Não foi possível vincular a conta OAuth.'
            );
        }

        return $user;
    }
}
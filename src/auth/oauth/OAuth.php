<?php

namespace nucleo\auth\oauth;

use nucleo\auth\oauth\contracts\OAuthProvider;

class OAuth
{
    private static array $providers = [];

    public static function register(
        string $name,
        OAuthProvider $provider
    ): void {
        if (
            trim($name) === ''
        ) {
            throw new \InvalidArgumentException(
                'O nome do provider OAuth não pode ser vazio.'
            );
        }

        self::$providers[$name] = $provider;
    }

    public static function provider(
        string $name
    ): OAuthProvider {
        if (!isset(self::$providers[$name])) {
            throw new \RuntimeException(
                sprintf(
                    'O provider OAuth "%s" não está registrado.',
                    $name
                )
            );
        }

        return self::$providers[$name];
    }

    public static function has(
        string $name
    ): bool {
        return isset(self::$providers[$name]);
    }

    public static function providers(): array
    {
        return self::$providers;
    }
}

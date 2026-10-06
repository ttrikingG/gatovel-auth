<?php

namespace nucleo\auth\oauth;

use nucleo\auth\oauth\exceptions\OAuthException;
use nucleo\session\Session;

class OAuthState
{
    private const SESSION_KEY = '_oauth_state';

    public static function generate(): string
    {
        $state = bin2hex(
            random_bytes(32)
        );

        Session::set(
            self::SESSION_KEY,
            $state
        );

        return $state;
    }

    public static function validate(
        string $state
    ): void {
        $storedState = Session::get(
            self::SESSION_KEY
        );

        Session::remove(
            self::SESSION_KEY
        );

        if (
            !is_string($storedState)
            || $storedState === ''
        ) {
            throw new OAuthException(
                'Estado OAuth não encontrado na sessão.'
            );
        }

        if (
            $state === ''
            || !hash_equals(
                $storedState,
                $state
            )
        ) {
            throw new OAuthException(
                'Estado OAuth inválido.'
            );
        }
    }
}

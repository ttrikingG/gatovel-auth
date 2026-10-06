<?php

namespace nucleo\auth\mfa;

use nucleo\session\Session;

class MfaChallenge
{
    private const SESSION_KEY = '_mfa_challenge_user_id';

    private const EXPIRES_KEY = '_mfa_challenge_expires_at';

    private const TTL = 300;

    public static function start(
        mixed $userId
    ): void {
        Session::set(
            self::SESSION_KEY,
            $userId
        );

        Session::set(
            self::EXPIRES_KEY,
            time() + self::TTL
        );
    }

    public static function has(): bool
    {
        if (
            !Session::has(
                self::SESSION_KEY
            )
        ) {
            return false;
        }

        $expiresAt = Session::get(
            self::EXPIRES_KEY
        );

        if (
            !is_int($expiresAt)
            || time() >= $expiresAt
        ) {
            self::clear();

            return false;
        }

        return true;
    }

    public static function userId(): mixed
    {
        if (!self::has()) {
            return null;
        }

        return Session::get(
            self::SESSION_KEY
        );
    }

    public static function clear(): void
    {
        Session::remove(
            self::SESSION_KEY
        );

        Session::remove(
            self::EXPIRES_KEY
        );
    }
}
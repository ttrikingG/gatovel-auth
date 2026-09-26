<?php

namespace nucleo\auth\session;

class Session
{
    public static function start(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start([
                'cookie_httponly' => true,
                'cookie_samesite' => 'Lax',
                'use_strict_mode' => true,
            ]);
        }
    }

    public static function set(string $key, mixed $value): void
    {
        self::start();

        $_SESSION[$key] = $value;
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        self::start();

        return $_SESSION[$key] ?? $default;
    }

    public static function has(string $key): bool
    {
        self::start();

        return isset($_SESSION[$key]);
    }

    public static function remove(string $key): void
    {
        self::start();

        unset($_SESSION[$key]);
    }

    public static function regenerate(): void
    {
        self::start();

        session_regenerate_id(true);
    }

    public static function destroy(): void
    {
        self::start();

        $_SESSION = [];

        session_destroy();
    }
}



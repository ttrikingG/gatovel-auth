<?php

namespace nucleo\auth\authentication;

use nucleo\auth\contracts\Authenticatable;
use nucleo\auth\contracts\EmailVerificationService;
use nucleo\auth\contracts\MfaService;
use nucleo\auth\contracts\UserProvider;
use nucleo\auth\mfa\MfaChallenge;
use nucleo\session\Session;

class Auth
{
    private const SESSION_KEY = 'auth_user_id';

    private static ?UserProvider $provider = null;

    private static ?EmailVerificationService $emailVerification = null;

    private static ?MfaService $mfa = null;

    private static bool $emailVerificationRequired = false;

    public static function setProvider(
        UserProvider $provider
    ): void {
        self::$provider = $provider;
    }

    public static function setEmailVerificationService(
        EmailVerificationService $service
    ): void {
        self::$emailVerification = $service;
    }

    public static function setMfaService(
        MfaService $service
    ): void {
        self::$mfa = $service;
    }

    public static function attempt(
        string $email,
        string $password
    ): bool {
        self::$emailVerificationRequired = false;

        if (self::$provider === null) {
            return false;
        }

        $user = self::$provider->retrieveByCredentials([
            'email' => $email,
        ]);

        if ($user === null) {
            return false;
        }

        if (!Password::verify(
            $password,
            $user->getAuthPassword()
        )) {
            return false;
        }

        if (
            self::$emailVerification !== null
            && !self::$emailVerification->isVerified(
                $user
            )
        ) {
            self::$emailVerificationRequired = true;

            return false;
        }

        if (
            self::$mfa !== null
            && self::$mfa->isEnabled(
                $user
            )
        ) {
            MfaChallenge::start(
                $user->getAuthIdentifier()
            );

            return true;
        }

        self::login($user);

        return true;
    }

    public static function emailVerificationRequired(): bool
    {
        return self::$emailVerificationRequired;
    }

    public static function completeMfa(
        string $code
    ): bool {
        if (!MfaChallenge::has()) {
            return false;
        }

        if (self::$provider === null) {
            return false;
        }

        if (self::$mfa === null) {
            return false;
        }

        $userId = MfaChallenge::userId();

        $user = self::$provider->retrieveById(
            $userId
        );

        if ($user === null) {
            MfaChallenge::clear();

            return false;
        }

        if (
            !self::$mfa->verify(
                $user,
                $code
            )
        ) {
            return false;
        }

        MfaChallenge::clear();

        self::login(
            $user
        );

        return true;
    }

    public static function mfaRequired(): bool
    {
        return MfaChallenge::has();
    }

    public static function mfaUser(): ?Authenticatable
    {
        if (!MfaChallenge::has()) {
            return null;
        }

        if (self::$provider === null) {
            return null;
        }

        return self::$provider->retrieveById(
            MfaChallenge::userId()
        );
    }

    public static function login(
        Authenticatable $user
    ): void {
        Session::start();

        MfaChallenge::clear();

        Session::regenerate();

        Session::set(
            self::SESSION_KEY,
            $user->getAuthIdentifier()
        );
    }

    public static function logout(): void
    {
        MfaChallenge::clear();

        Session::remove(
            self::SESSION_KEY
        );

        Session::regenerate();
    }

    public static function check(): bool
    {
        return Session::has(
            self::SESSION_KEY
        );
    }

    public static function user(): ?Authenticatable
    {
        if (!self::check()) {
            return null;
        }

        if (self::$provider === null) {
            return null;
        }

        $userId = Session::get(
            self::SESSION_KEY
        );

        return self::$provider->retrieveById(
            $userId
        );
    }
}

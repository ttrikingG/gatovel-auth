<?php

namespace nucleo\auth\verification;

use nucleo\auth\contracts\Authenticatable;
use nucleo\auth\contracts\UserRepository;
use nucleo\mail\Mail;
use nucleo\mail\Message;

class EmailVerification
{
    private static ?UserRepository $repository = null;

    public static function setRepository(
        UserRepository $repository
    ): void {
        self::$repository = $repository;
    }

    public static function create(
        int $userId
    ): ?string {
        if (self::$repository === null) {
            return null;
        }

        $user = self::$repository->find(
            $userId
        );

        if ($user === null) {
            return null;
        }

        if (
            self::isVerifiedUser($user)
        ) {
            return null;
        }

        return EmailVerificationToken::create(
            $userId
        );
    }

    public static function buildUrl(
        string $token
    ): string {
        return '/verify-email/'
            . urlencode($token);
    }

    public static function send(
        int $userId
    ): bool {
        if (self::$repository === null) {
            return false;
        }

        $user = self::$repository->find(
            $userId
        );

        if ($user === null) {
            return false;
        }

        if (
            self::isVerifiedUser($user)
        ) {
            return false;
        }

        $token = self::create(
            $userId
        );

        if ($token === null) {
            return false;
        }

        return self::sendToken(
            $user,
            $token
        );
    }

    public static function resend(
        string $email
    ): bool {
        if (self::$repository === null) {
            return false;
        }

        $email = trim(
            strtolower($email)
        );

        if ($email === '') {
            return false;
        }

        $user = self::$repository->findByEmail(
            $email
        );

        if ($user === null) {
            return false;
        }

        if (
            self::isVerifiedUser($user)
        ) {
            return false;
        }

        $identifier = $user->getAuthIdentifier();

        if (!is_int($identifier)) {
            return false;
        }

        return self::send(
            $identifier
        );
    }

    private static function sendToken(
        Authenticatable $user,
        string $token
    ): bool {
        $url = self::buildUrl(
            $token
        );

        $message = new Message();

        $message
            ->to(
                (string) $user->email
            )
            ->subject(
                'Verifique seu e-mail'
            )
            ->body(
                "Olá, {$user->name}!"
                . PHP_EOL
                . PHP_EOL
                . "Para verificar seu e-mail, "
                . "acesse o link abaixo:"
                . PHP_EOL
                . PHP_EOL
                . $url
                . PHP_EOL
                . PHP_EOL
                . "Este link é válido por 24 horas."
            );

        return Mail::send(
            $message
        );
    }

    public static function verifyToken(
        string $token
    ): bool {
        if (self::$repository === null) {
            return false;
        }

        $userId = EmailVerificationToken::findUserId(
            $token
        );

        if ($userId === null) {
            return false;
        }

        $user = self::$repository->find(
            $userId
        );

        if ($user === null) {
            return false;
        }

        if (
            self::isVerifiedUser($user)
        ) {
            EmailVerificationToken::invalidateForUser(
                $userId
            );

            return true;
        }

        $user->email_verified_at = date(
            'Y-m-d H:i:s'
        );

        if (
            !self::$repository->save($user)
        ) {
            return false;
        }

        EmailVerificationToken::invalidateForUser(
            $userId
        );

        return true;
    }

    public static function isVerified(
        int $userId
    ): bool {
        if (self::$repository === null) {
            return false;
        }

        $user = self::$repository->find(
            $userId
        );

        if ($user === null) {
            return false;
        }

        return self::isVerifiedUser(
            $user
        );
    }

    private static function isVerifiedUser(
        Authenticatable $user
    ): bool {
        return $user->email_verified_at !== null;
    }
}

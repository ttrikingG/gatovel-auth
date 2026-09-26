<?php

namespace nucleo\auth\oauth\contracts;

interface OAuthProvider
{
    public function getAuthorizationUrl(
        string $state
    ): string;

    public function getAccessToken(
        string $code
    ): string;

    public function getUser(
        string $accessToken
    ): array;
}

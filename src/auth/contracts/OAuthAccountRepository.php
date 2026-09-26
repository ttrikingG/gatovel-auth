<?php

namespace nucleo\auth\contracts;

interface OAuthAccountRepository
{
    public function findUserId(
        string $provider,
        string $providerUserId
    ): ?int;

    public function create(
        int $userId,
        string $provider,
        string $providerUserId
    ): bool;
}

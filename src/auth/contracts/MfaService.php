<?php

namespace nucleo\auth\contracts;

interface MfaService
{
    public function isEnabled(
        Authenticatable $user
    ): bool;

    public function verify(
        Authenticatable $user,
        string $code
    ): bool;
}

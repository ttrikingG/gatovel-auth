<?php

namespace nucleo\auth\contracts;

interface EmailVerificationService
{
    public function isVerified(
        Authenticatable $user
    ): bool;
}

<?php

namespace nucleo\auth\contracts;

interface UserProvider
{
    public function retrieveByCredentials(
        array $credentials
    ): ?Authenticatable;

    public function retrieveById(
        mixed $identifier
    ): ?Authenticatable;
}
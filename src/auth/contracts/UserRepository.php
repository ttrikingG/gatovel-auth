<?php

namespace nucleo\auth\contracts;

interface UserRepository
{
    public function find(
        mixed $identifier
    ): ?Authenticatable;

    public function findByEmail(
        string $email
    ): ?Authenticatable;

    public function save(
        Authenticatable $user
    ): bool;

    public function create(
        array $attributes
    ): ?Authenticatable;
}

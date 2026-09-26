<?php

namespace nucleo\auth\contracts;

interface Authenticatable
{
    public function getAuthIdentifier(): mixed;

    public function getAuthPassword(): string;
}
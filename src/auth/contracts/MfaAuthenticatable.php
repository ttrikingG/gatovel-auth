<?php

namespace nucleo\auth\contracts;

interface MfaAuthenticatable extends Authenticatable
{
    public function getAuthEmail(): string;
}

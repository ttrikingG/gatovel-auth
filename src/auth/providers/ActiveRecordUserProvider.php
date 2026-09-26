<?php

namespace nucleo\auth\providers;

use nucleo\auth\contracts\Authenticatable;
use nucleo\auth\contracts\UserProvider;

class ActiveRecordUserProvider implements UserProvider
{
    public function __construct(
        private string $model
    ) {
    }

    public function retrieveByCredentials(
        array $credentials
    ): ?Authenticatable {
        $email = $credentials['email'] ?? null;

        if (
            !is_string($email)
            || $email === ''
        ) {
            return null;
        }

        $data = $this->model::where(
            'email',
            $email
        )->first();

        if (
            !is_array($data)
            || $data === []
        ) {
            return null;
        }

        return new $this->model(
            $data
        );
    }

    public function retrieveById(
        mixed $identifier
    ): ?Authenticatable {
        $user = $this->model::find(
            $identifier
        );

        if ($user === null) {
            return null;
        }

        return $user;
    }
}
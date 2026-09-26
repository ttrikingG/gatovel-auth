<?php

namespace nucleo\auth\oauth\providers;

use nucleo\auth\oauth\contracts\OAuthProvider;
use nucleo\auth\oauth\exceptions\OAuthException;

class GoogleProvider implements OAuthProvider
{
    private const AUTHORIZATION_URL =
        'https://accounts.google.com/o/oauth2/v2/auth';

    private const TOKEN_URL =
        'https://oauth2.googleapis.com/token';

    private const USER_INFO_URL =
        'https://openidconnect.googleapis.com/v1/userinfo';

    public function __construct(
        private string $clientId,
        private string $clientSecret,
        private string $redirectUri
    ) {
        if (
            trim($this->clientId) === ''
            || trim($this->clientSecret) === ''
            || trim($this->redirectUri) === ''
        ) {
            throw new OAuthException(
                'As configurações do Google OAuth não foram definidas.'
            );
        }
    }

    public function getAuthorizationUrl(
        string $state
    ): string {
        if (trim($state) === '') {
            throw new OAuthException(
                'O parâmetro state do OAuth não pode ser vazio.'
            );
        }

        $parameters = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $state,
        ];

        return self::AUTHORIZATION_URL
            . '?'
            . http_build_query(
                $parameters,
                '',
                '&',
                PHP_QUERY_RFC3986
            );
    }

    public function getAccessToken(
        string $code
    ): string {
        if (trim($code) === '') {
            throw new OAuthException(
                'O authorization code não pode ser vazio.'
            );
        }

        $response = $this->request(
            self::TOKEN_URL,
            [
                'code' => $code,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'redirect_uri' => $this->redirectUri,
                'grant_type' => 'authorization_code',
            ]
        );

        $accessToken = $response['access_token'] ?? null;

        if (
            !is_string($accessToken)
            || $accessToken === ''
        ) {
            throw new OAuthException(
                'O Google não retornou um access token válido.'
            );
        }

        return $accessToken;
    }

    public function getUser(
        string $accessToken
    ): array {
        if (trim($accessToken) === '') {
            throw new OAuthException(
                'O access token não pode ser vazio.'
            );
        }

        $response = $this->request(
            self::USER_INFO_URL,
            [],
            [
                'Authorization: Bearer ' . $accessToken,
                'Accept: application/json',
            ]
        );

        return $response;
    }

    private function request(
        string $url,
        array $data = [],
        array $headers = []
    ): array {
        $curl = curl_init();

        if ($curl === false) {
            throw new OAuthException(
                'Não foi possível inicializar o cliente HTTP.'
            );
        }

        $options = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_HTTPHEADER => array_merge(
                [
                    'Accept: application/json',
                ],
                $headers
            ),
        ];

        if ($data !== []) {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = http_build_query(
                $data,
                '',
                '&',
                PHP_QUERY_RFC3986
            );

            $options[CURLOPT_HTTPHEADER][] =
                'Content-Type: application/x-www-form-urlencoded';
        }

        curl_setopt_array(
            $curl,
            $options
        );

        $body = curl_exec($curl);

        if ($body === false) {
            $error = curl_error($curl);

            curl_close($curl);

            throw new OAuthException(
                'Erro na comunicação com o Google: ' . $error
            );
        }

        $status = curl_getinfo(
            $curl,
            CURLINFO_HTTP_CODE
        );

        curl_close($curl);

        $response = json_decode(
            $body,
            true
        );

        if (!is_array($response)) {
            throw new OAuthException(
                'O Google retornou uma resposta inválida.'
            );
        }

        if ($status < 200 || $status >= 300) {
            $message = $response['error_description']
                ?? $response['error']
                ?? 'Erro desconhecido.';

            throw new OAuthException(
                'Erro na requisição OAuth do Google: '
                . $message
            );
        }

        return $response;
    }
}

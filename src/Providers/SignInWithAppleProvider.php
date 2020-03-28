<?php

namespace GeneaLabs\LaravelSignInWithApple\Providers;

use Illuminate\Support\Arr;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use InvalidArgumentException;

/**
 * Class SignInWithAppleProvider
 * @package GeneaLabs\LaravelSignInWithApple\Providers
 */
class SignInWithAppleProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * @var int
     */
    protected $encodingType = PHP_QUERY_RFC3986;

    /**
     * @var string
     */
    protected $scopeSeparator = " ";

    /**
     * @param string $state
     * @return string
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            'https://appleid.apple.com/auth/authorize',
            $state
        );
    }

    /**
     * @param null $state
     * @return array
     */
    protected function getCodeFields($state = null)
    {
        $fields = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'response_type' => 'code',
            'response_mode' => 'form_post',
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        return array_merge($fields, $this->parameters);
    }

    /**
     * @return string
     */
    protected function getTokenUrl()
    {
        return "https://appleid.apple.com/auth/token";
    }

    /**
     * @param $code
     * @return mixed
     */
    public function getAccessToken($code)
    {
        $response = $this->getHttpClient()
            ->post(
                $this->getTokenUrl(),
                [
                    'headers' => [
                        'Authorization' => 'Basic '. base64_encode(
                            $this->clientId . ':' . $this->clientSecret
                        ),
                    ],
                    'body' => $this->getTokenFields($code),
                ]
            );

        return $this->parseAccessToken($response->getBody());
    }

    /**
     * @param $response
     * @return mixed
     */
    protected function parseAccessToken($response)
    {
        $data = $response->json();

        return $data['access_token'];
    }

    /**
     * @param string $code
     * @return array
     */
    protected function getTokenFields($code)
    {
        $fields = parent::getTokenFields($code);
        $fields["grant_type"] = "authorization_code";

        return $fields;
    }

    /**
     * @param string $token
     * @return array|mixed
     */
    protected function getUserByToken($token)
    {
        $claims = explode('.', $token)[1];

        return json_decode(base64_decode($claims), true);
    }

    /**
     * @return \Laravel\Socialite\Contracts\User|User
     */
    public function user()
    {
        $response = $this->getAccessTokenResponse($this->getCode());

        $user = $this->mapUserToObject($this->getUserByToken(
            Arr::get($response, 'id_token')
        ));

        return $user
            ->setToken(Arr::get($response, 'access_token'))
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

    /**
     * Map user data to a User object.
     *
     * @param array $user
     * @return User
     */
    protected function mapUserToObject(array $user)
    {
        if (request()->filled("user")) {
            $userRequest = json_decode(request("user"), true);

            if (array_key_exists("name", $userRequest)) {
                $user["name"] = $userRequest["name"];
                $fullName = trim(
                    ($user["name"]['firstName'] ?? "")
                    . " "
                    . ($user["name"]['lastName'] ?? "")
                );
            }
        }

        return (new User)
            ->setRaw($user)
            ->map([
                "id" => $user["sub"],
                "name" => $fullName ?? null,
                "email" => $user["email"] ?? null,
            ]);
    }

    /**
     * Decode the JWT and verify with Apple's public keys
     *
     * @param $jwt
     * @return object
     * @throws \Exception
     */
    protected function decodeJwt($jwt)
    {
        // Hard coding the alg for now since only RS256 is currently supported
        $jwt = JWT::decode($jwt, $this->fetchPublicKeysFromApple(), ["RS256"]);

        return (array) $jwt;
    }

    /**
     * URL for Apples Public Keys in JWKS format
     *
     * @return string
     */
    protected function getKeyUrl()
    {
        return "https://appleid.apple.com/auth/keys";
    }

    /**
     * Fetch and parse the public keys from Apple. The returned
     * keys are in JWKS format and they need to be parsed into
     * a key set that the JWT decoder can handle
     *
     * @return mixed
     * @throws \Exception
     */
    protected function fetchPublicKeysFromApple()
    {
        // Retrieve the JWKS from Apple's public API
        $response = $this->getHttpClient()->get($this->getKeyUrl());
        $jwks = json_decode($response->getBody(), true);

        if (!isset($jwks['keys']) || count($jwks['keys']) < 1) {
            throw new \Exception('Invalid JWKS format.');
        }

        // Parse the JWKS returned from Apple into a Key set that the JWT decoder will understand
        $keySet = JWK::parseKeySet($jwks);

        return $keySet;
    }

    /**
     * Make sure the issuer and audience data matches what we expect.
     * This is an extra check and may be unnecessary, but it's not a bad idea.
     *
     * @param $jwtData
     * @return bool
     * @throws \Exception
     */
    public function verifyJwtData($jwtData)
    {
        if (!is_array($jwtData)) {
            throw new InvalidArgumentException("Invalid JWT format. Type is " . gettype($jwtData));
        }

        // Check the issuer
        if ($jwtData["iss"] != "https://appleid.apple.com") {
            throw new InvalidArgumentException("Invalid issuer.");
        }

        // Check the audience: should be the app id from the Apple Developer Console
        if ($jwtData["aud"] != config('services.sign_in_with_apple.app_id')) {
            throw new InvalidArgumentException("App Id does not match aud variable in JWT.");
        }

        return true;
    }

    /**
     * Take the JWT passed from the frontend and create
     * a new User object.
     *
     * @param $jwt
     * @return User
     * @throws \Exception
     */
    public function userFromJwt($jwt)
    {
        $data = $this->decodeJwt($jwt);
        if ($this->verifyJwtData($data)) {

            return (new User)
                ->setToken($jwt)
                ->map([
                    "id" => $data["sub"],
                    "name" => '',
                    "email" => $data["email"]
                ]);
        } else {
            return null;
        }
    }
}

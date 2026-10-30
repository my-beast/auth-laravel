<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel\Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\Factory as Http;
use MyBeast\Auth\Laravel\Exceptions\SignInFailed;
use Throwable;

/**
 * The environment's OpenID Connect provider, as this app talks to it: its discovery document and JWKS (cached; an
 * ID token signed by a key not in the cached JWKS reads it again once), the code for tokens, and the ID token checked
 * - ES256 signature, issuer, audience, expiry, nonce.
 */
final class Provider
{
    private const LEEWAY = 60;

    public function __construct(
        private readonly Http $http,
        private readonly Cache $cache,
        private readonly string $issuer,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly int $cacheSeconds,
        private readonly float $timeout,
    ) {}

    public function issuer(): string
    {
        return $this->issuer;
    }

    public function clientId(): string
    {
        return $this->clientId;
    }

    /** @return array<string, mixed> */
    public function discovery(): array
    {
        return $this->cache->remember($this->key('discovery'), $this->cacheSeconds, function (): array {
            $document = $this->get($this->issuer.'/.well-known/openid-configuration');

            if (($document['issuer'] ?? null) !== $this->issuer) {
                throw new SignInFailed('The discovery document names another issuer.');
            }

            return $document;
        });
    }

    public function endpoint(string $name): string
    {
        $url = $this->discovery()[$name] ?? null;

        return is_string($url) ? $url : throw new SignInFailed("The provider has no {$name}.");
    }

    /** @return array{id_token: string, access_token: string} */
    public function exchange(string $code, string $redirectUri, string $verifier): array
    {
        try {
            $response = $this->http->asForm()->acceptJson()->timeout($this->timeout)
                ->withBasicAuth(urlencode($this->clientId), urlencode($this->clientSecret))
                ->post($this->endpoint('token_endpoint'), [
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                    'redirect_uri' => $redirectUri,
                    'code_verifier' => $verifier,
                ]);
        } catch (Throwable $failure) {
            throw new SignInFailed('The provider did not answer.', previous: $failure);
        }

        if (! $response->successful() || ! is_string($response->json('id_token'))) {
            throw new SignInFailed('No tokens for the code: '.($response->json('error') ?? $response->status()));
        }

        return ['id_token' => (string) $response->json('id_token'), 'access_token' => (string) $response->json('access_token')];
    }

    /** @return array<string, mixed> the ID token's claims, checked */
    public function verify(string $idToken, string $nonce): array
    {
        $kid = $this->kid($idToken);

        try {
            $claims = $this->decode($idToken, $this->keys(), $kid);
        } catch (SignInFailed $unknownKey) {
            // A key published after the JWKS was cached: read it again, once.
            $this->cache->forget($this->key('jwks'));
            $claims = $this->decode($idToken, $this->keys(), $kid);
        }

        $aud = $claims['aud'] ?? null;

        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new SignInFailed('The ID token is from another issuer.');
        }

        if (! ($aud === $this->clientId || (is_array($aud) && in_array($this->clientId, $aud, true)))) {
            throw new SignInFailed('The ID token is for another app.');
        }

        if (! is_string($claims['nonce'] ?? null) || ! hash_equals($nonce, $claims['nonce'])) {
            throw new SignInFailed('The ID token is not this sign-in\'s.');
        }

        if (! is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new SignInFailed('The ID token names nobody.');
        }

        return $claims;
    }

    /** @return array<string, Key> */
    private function keys(): array
    {
        $jwks = $this->cache->remember($this->key('jwks'), $this->cacheSeconds, fn (): array => $this->get($this->endpoint('jwks_uri')));

        try {
            return JWK::parseKeySet($jwks, 'ES256');
        } catch (Throwable $failure) {
            throw new SignInFailed('The provider\'s keys do not read.', previous: $failure);
        }
    }

    /**
     * @param  array<string, Key>  $keys
     * @return array<string, mixed>
     */
    private function decode(string $jwt, array $keys, string $kid): array
    {
        if (! isset($keys[$kid])) {
            throw new SignInFailed('The ID token is signed by a key the provider does not publish.');
        }

        $leeway = JWT::$leeway;
        JWT::$leeway = self::LEEWAY;

        try {
            return json_decode(json_encode(JWT::decode($jwt, $keys)), true);
        } catch (Throwable $failure) {
            throw new SignInFailed('The ID token does not check out: '.$failure->getMessage(), previous: $failure);
        } finally {
            JWT::$leeway = $leeway;
        }
    }

    private function kid(string $jwt): string
    {
        $header = json_decode((string) base64_decode(strtr(explode('.', $jwt)[0], '-_', '+/'), true), true);

        if (! is_array($header) || ($header['alg'] ?? null) !== 'ES256' || ! is_string($header['kid'] ?? null)) {
            throw new SignInFailed('The ID token is not ES256 with a key id.');
        }

        return $header['kid'];
    }

    /** @return array<string, mixed> */
    private function get(string $url): array
    {
        try {
            $response = $this->http->acceptJson()->timeout($this->timeout)->get($url);
        } catch (Throwable $failure) {
            throw new SignInFailed('The provider did not answer.', previous: $failure);
        }

        return $response->successful() && is_array($response->json()) ? $response->json() : throw new SignInFailed("The provider answered {$response->status()} at {$url}.");
    }

    private function key(string $part): string
    {
        return 'mybeast-auth:'.$part.':'.hash('sha256', $this->issuer);
    }
}

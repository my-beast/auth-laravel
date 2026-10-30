<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel\Tests;

use Firebase\JWT\JWT;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use MyBeast\Auth\Laravel\Facades\MyBeastAuth;
use MyBeast\Auth\Laravel\Identity;
use MyBeast\Auth\Laravel\MyBeastAuthServiceProvider;
use Orchestra\Testbench\Attributes\WithMigration;
use Orchestra\Testbench\TestCase as Orchestra;

/**
 * A host app and the provider it signs in with: the provider's discovery, JWKS and /token answered by Http::fake,
 * its ID tokens signed here with a P-256 key as Auth signs them.
 */
#[WithMigration]
abstract class TestCase extends Orchestra
{
    protected const ISSUER = 'https://auth.test/e/env_0123456789abcdef';

    protected const CLIENT_ID = 'ac_testclient';

    protected \OpenSSLAsymmetricKey $key;

    protected string $kid = 'k_one';

    /** What /token answers next: claims of the ID token (null: an error). */
    protected ?array $tokenClaims = null;

    protected array $tokenRequests = [];

    /** The last ID token the stand-in /token handed out. */
    protected ?string $issuedIdToken = null;

    protected function getPackageProviders($app): array
    {
        return [MyBeastAuthServiceProvider::class];
    }

    protected function getPackageAliases($app): array
    {
        return ['MyBeastAuth' => MyBeastAuth::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('cache.default', 'array');
        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('mybeast-auth.issuer', self::ISSUER);
        $app['config']->set('mybeast-auth.client_id', self::CLIENT_ID);
        $app['config']->set('mybeast-auth.client_secret', 'the-secret');
        $app['config']->set('mybeast-auth.home', '/home');
        $app['config']->set('mybeast-auth.url', 'https://auth.test');
        $app['config']->set('mybeast-auth.server_secret', 'sk_abc.def');
        $app['config']->set('mybeast-auth.environment', 'production');
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadLaravelMigrations();
    }

    protected function defineRoutes($router): void
    {
        Route::middleware(['web', 'auth'])->get('/home', fn () => 'home of '.auth()->user()->email);
        Route::middleware(['web', 'auth', 'mybeast-auth.fresh:15'])->get('/billing', fn () => 'billing');
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $this->provide();

        // The app: an Auth person is the user with their sub, made on first sign-in.
        MyBeastAuth::resolveUsersWith(function (Identity $who): User {
            $user = User::query()->where('email', $who->email)->first() ?? new User;
            $user->forceFill(['name' => $who->name ?? 'Someone', 'email' => (string) $who->email, 'password' => 'x'])->save();

            return $user;
        });
    }

    protected function provide(): void
    {
        Http::swap(new Factory($this->app['events']));
        Http::fake(function ($request) {
            $url = $request->url();

            return match (true) {
                $url === self::ISSUER.'/.well-known/openid-configuration' => Http::response([
                    'issuer' => self::ISSUER,
                    'authorization_endpoint' => self::ISSUER.'/authorize',
                    'token_endpoint' => self::ISSUER.'/token',
                    'jwks_uri' => self::ISSUER.'/jwks',
                    'end_session_endpoint' => self::ISSUER.'/sign-out',
                ]),
                $url === self::ISSUER.'/jwks' => Http::response(['keys' => [$this->jwk()]]),
                $url === self::ISSUER.'/token' => $this->tokenAnswer($request),
                str_starts_with($url, 'https://auth.test/api/') => Http::response(['id' => 'u-1', 'email' => 'pat@example.test', 'status' => 'active', 'signed_out_devices' => 2]),
                default => Http::response([], 404),
            };
        });
    }

    protected function tokenAnswer($request)
    {
        $this->tokenRequests[] = $request;

        if ($this->tokenClaims === null) {
            return Http::response(['error' => 'invalid_grant'], 400);
        }

        $this->issuedIdToken = $this->idToken($this->tokenClaims);

        return Http::response(['access_token' => 'at', 'token_type' => 'Bearer', 'expires_in' => 600, 'id_token' => $this->issuedIdToken]);
    }

    /** @param  array<string, mixed>  $claims */
    protected function idToken(array $claims, ?string $kid = null): string
    {
        openssl_pkey_export($this->key, $pem);

        return JWT::encode($claims, $pem, 'ES256', $kid ?? $this->kid);
    }

    /** @return array<string, string> */
    protected function jwk(): array
    {
        $ec = openssl_pkey_get_details($this->key)['ec'];
        $b64 = fn (string $bytes): string => rtrim(strtr(base64_encode(str_pad($bytes, 32, "\0", STR_PAD_LEFT)), '+/', '-_'), '=');

        return ['kty' => 'EC', 'crv' => 'P-256', 'x' => $b64($ec['x']), 'y' => $b64($ec['y']), 'kid' => $this->kid, 'use' => 'sig', 'alg' => 'ES256'];
    }

    /** @return array<string, string> the query the app sent the browser to /authorize with */
    protected function startSignIn(string $path = '/mybeast-auth/redirect'): array
    {
        $location = (string) $this->get($path)->assertRedirect()->headers->get('Location');
        $this->assertStringStartsWith(self::ISSUER.'/authorize?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        return $query;
    }

    /** @return array<string, mixed> an ID token's claims for this sign-in */
    protected function claims(array $query, array $override = []): array
    {
        return $override + [
            'iss' => self::ISSUER,
            'aud' => self::CLIENT_ID,
            'sub' => '0199a000-0000-7000-8000-000000000001',
            'email' => 'pat@example.test',
            'email_verified' => true,
            'name' => 'Pat',
            'nonce' => $query['nonce'],
            'iat' => time(),
            'exp' => time() + 600,
            'auth_time' => time(),
            'amr' => ['pwd'],
        ];
    }
}

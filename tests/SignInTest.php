<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel\Tests;

use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;
use MyBeast\Auth\Laravel\Facades\MyBeastAuth;

final class SignInTest extends TestCase
{
    public function test_the_redirect_asks_for_a_code_with_pkce_a_state_and_a_nonce(): void
    {
        $query = $this->startSignIn('/mybeast-auth/redirect?return=/billing');

        $this->assertSame('code', $query['response_type']);
        $this->assertSame(self::CLIENT_ID, $query['client_id']);
        $this->assertSame('http://localhost/mybeast-auth/callback', $query['redirect_uri']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertSame('openid email profile', $query['scope']);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $query['code_challenge']);
        $this->assertNotSame($query['state'], $query['nonce']);
    }

    public function test_the_callback_checks_the_id_token_and_signs_the_user_in(): void
    {
        $query = $this->startSignIn('/mybeast-auth/redirect?return=/billing');
        $this->tokenClaims = $this->claims($query);

        $this->get('/mybeast-auth/callback?code=the-code&state='.$query['state'])->assertRedirect('/billing');
        $this->assertAuthenticated();
        $this->assertSame('pat@example.test', auth()->user()->email);
        $identity = MyBeastAuth::identity();
        $this->assertSame('0199a000-0000-7000-8000-000000000001', $identity->sub);
        $this->assertSame(['pwd'], $identity->amr);
        $this->assertTrue($identity->emailVerified);

        // The code went with the client's secret (Basic) and the PKCE verifier that hashes to the challenge.
        $token = $this->tokenRequests[0];
        $this->assertSame('Basic '.base64_encode(self::CLIENT_ID.':the-secret'), $token->header('Authorization')[0]);
        $this->assertSame($query['code_challenge'], rtrim(strtr(base64_encode(hash('sha256', $token['code_verifier'], true)), '+/', '-_'), '='));
        $this->get('/billing')->assertOk()->assertSee('billing');
    }

    public function test_a_wrong_state_nonce_audience_issuer_signature_or_age_signs_nobody_in(): void
    {
        $cases = [
            'state' => fn (array $q): array => [$this->claims($q), 'forged'],
            'nonce' => fn (array $q): array => [$this->claims($q, ['nonce' => 'other']), $q['state']],
            'aud' => fn (array $q): array => [$this->claims($q, ['aud' => 'ac_other']), $q['state']],
            'iss' => fn (array $q): array => [$this->claims($q, ['iss' => 'https://evil.test']), $q['state']],
            'exp' => fn (array $q): array => [$this->claims($q, ['exp' => time() - 3600]), $q['state']],
        ];

        foreach ($cases as $what => $case) {
            $query = $this->startSignIn();
            [$this->tokenClaims, $state] = $case($query);
            $this->get('/mybeast-auth/callback?code=c&state='.$state)->assertRedirect('/home')->assertSessionHas('mybeast-auth.error');
            $this->assertGuest(null);
            $this->assertNull(MyBeastAuth::identity(), "A wrong {$what} signed someone in.");
        }

        // Signed with a key the provider does not publish, even after reading its keys again.
        $query = $this->startSignIn();
        $this->tokenClaims = $this->claims($query);
        $this->kid = 'k_one';
        $this->key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $published = $this->jwk();
        Http::swap(new Factory($this->app['events']));
        $this->key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        Http::fake([
            self::ISSUER.'/.well-known/openid-configuration' => Http::response(['issuer' => self::ISSUER, 'authorization_endpoint' => self::ISSUER.'/authorize', 'token_endpoint' => self::ISSUER.'/token', 'jwks_uri' => self::ISSUER.'/jwks', 'end_session_endpoint' => self::ISSUER.'/sign-out']),
            self::ISSUER.'/jwks' => Http::response(['keys' => [$published]]),
            self::ISSUER.'/token' => Http::response(['id_token' => $this->idToken($this->tokenClaims)]),
        ]);
        $this->get('/mybeast-auth/callback?code=c&state='.$query['state'])->assertSessionHas('mybeast-auth.error');
        $this->assertGuest();
    }

    public function test_a_key_published_after_the_jwks_was_cached_is_fetched_once(): void
    {
        $query = $this->startSignIn();
        $this->tokenClaims = $this->claims($query);
        $this->get('/mybeast-auth/callback?code=c&state='.$query['state'])->assertRedirect('/home');
        $this->post('/mybeast-auth/sign-out');

        // Auth rotated: a new key id; the cached JWKS lacks it, so it is read again.
        $this->kid = 'k_two';
        $this->key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $query = $this->startSignIn();
        $this->tokenClaims = $this->claims($query);
        $this->get('/mybeast-auth/callback?code=c&state='.$query['state'])->assertRedirect('/home');
        $this->assertAuthenticated();
    }

    public function test_a_page_behind_fresh_asks_for_a_recent_sign_in(): void
    {
        $query = $this->startSignIn();
        $this->tokenClaims = $this->claims($query, ['auth_time' => time() - 20 * 60]);
        $this->get('/mybeast-auth/callback?code=c&state='.$query['state']);

        $this->get('/billing')->assertRedirect('/mybeast-auth/redirect?return=%2Fbilling&max_age=900');
        $again = $this->startSignIn('/mybeast-auth/redirect?return=%2Fbilling&max_age=900');
        $this->assertSame('900', $again['max_age']);
    }

    public function test_a_return_address_is_this_apps_own(): void
    {
        $query = $this->startSignIn('/mybeast-auth/redirect?return=//evil.test/x');
        $this->tokenClaims = $this->claims($query);

        $this->get('/mybeast-auth/callback?code=c&state='.$query['state'])->assertRedirect('/home');
    }

    public function test_the_app_may_refuse_a_person(): void
    {
        MyBeastAuth::resolveUsersWith(fn () => null);
        $query = $this->startSignIn();
        $this->tokenClaims = $this->claims($query);

        $this->get('/mybeast-auth/callback?code=c&state='.$query['state'])->assertSessionHas('mybeast-auth.error');
        $this->assertGuest();
    }

    public function test_sign_out_ends_the_session_here_and_goes_to_auth(): void
    {
        $query = $this->startSignIn();
        $this->tokenClaims = $this->claims($query);
        $this->get('/mybeast-auth/callback?code=c&state='.$query['state']);

        // This sign-in's ID token goes along: Auth signs the browser out at once only for the app that proves it asked.
        $this->post('/mybeast-auth/sign-out')->assertRedirect(self::ISSUER.'/sign-out?client_id='.self::CLIENT_ID.'&post_logout_redirect_uri='.rawurlencode('http://localhost').'&id_token_hint='.$this->issuedIdToken);
        $this->assertGuest();
    }

    public function test_the_users_api_takes_the_server_secret(): void
    {
        $this->assertSame('pat@example.test', MyBeastAuth::users()->findByEmail('pat@example.test')['email']);
        $this->assertSame(2, MyBeastAuth::users()->signOutEverywhere('u-1'));

        Http::assertSent(fn ($request): bool => $request->url() === 'https://auth.test/api/v1/environments/production/users?email=pat%40example.test'
            && $request->header('Authorization')[0] === 'Bearer sk_abc.def');
        Http::assertSent(fn ($request): bool => $request->url() === 'https://auth.test/api/v1/environments/production/users/u-1/sign-out' && $request->method() === 'POST');
    }

    public function test_the_fake_signs_a_test_in_as_anyone_through_the_apps_resolver(): void
    {
        MyBeastAuth::fake()->signInAs(['sub' => 'u-9', 'email' => 'nine@example.test', 'name' => 'Nine']);

        $this->get('/mybeast-auth/redirect?return=/billing')->assertRedirect();
        $this->followingRedirects()->get('/mybeast-auth/redirect?return=/billing')->assertOk()->assertSee('billing');
        $this->assertSame('nine@example.test', auth()->user()->email);
        $this->assertSame('u-9', MyBeastAuth::identity()->sub);
        Http::assertNothingSent();
    }

    public function test_acting_as_a_user_with_an_old_sign_in(): void
    {
        $user = new User;
        $user->forceFill(['name' => 'Old', 'email' => 'old@example.test', 'password' => 'x'])->save();

        MyBeastAuth::fake()->actingAs($user, ['sub' => 'u-old', 'auth_time' => time() - 3600]);
        $this->get('/home')->assertOk();
        $this->get('/billing')->assertRedirect();
    }
}

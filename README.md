# mybeast/auth-laravel

The Laravel SDK for MyBeast Auth (`services.my-beast.com/auth`): your app's people sign in on Auth's hosted pages
(password, e-mail code, passkey, Google/Microsoft/Apple, two-factor); your app gets who they are and keeps its own
users table and its own session. PHP ≥ 8.2, Laravel 12 and 13.

## Set up

```bash
composer require mybeast/auth-laravel
```

Make an app on the environment's **Apps** page at Auth, with its return address `https://your-app/mybeast-auth/callback`
(and, for signing out, `https://your-app/`). It shows these once:

```dotenv
MYBEAST_AUTH_ISSUER=https://services.my-beast.com/auth/e/env_…
MYBEAST_AUTH_CLIENT_ID=ac_…
MYBEAST_AUTH_CLIENT_SECRET=…
# the users API (optional): the project's server secret, Settings → Keys
MYBEAST_AUTH_URL=https://services.my-beast.com/auth
MYBEAST_AUTH_SERVER_SECRET=sk_….…
```

Say once who a signed-in person is in your app - store their `sub`:

```php
use MyBeast\Auth\Laravel\Facades\MyBeastAuth;
use MyBeast\Auth\Laravel\Identity;

MyBeastAuth::resolveUsersWith(function (Identity $who): ?User {
    return User::firstOrCreate(['auth_sub' => $who->sub], ['email' => $who->email, 'name' => $who->name]);
    // return null to keep someone out of this app
});
```

## Use

- Send people to `route('mybeast-auth.redirect', ['return' => '/dashboard'])` to sign in (or make it the guest
  redirect: `$middleware->redirectGuestsTo(fn () => route('mybeast-auth.redirect'))`). The callback checks the ID
  token (ES256 against the JWKS, issuer, audience, expiry, nonce; PKCE and a state), signs your user in to the guard
  (`MYBEAST_AUTH_GUARD`, else the default) with a new session id, and goes back to `return` (a path of this app only).
- `MyBeastAuth::identity()`: `sub`, `email`, `emailVerified`, `name`, `authTime`, `amr` (`pwd`, `otp`, `hwk` for a
  passkey, `fed` for a provider, `mfa` for two factors), `sid`.
- `->middleware('mybeast-auth.fresh:15')`: only with a sign-in from the last 15 minutes; otherwise Auth asks again
  (`max_age`) and the person comes back here.
- `POST route('mybeast-auth.sign-out')` (with `@csrf`): signed out here and at Auth, back to `MYBEAST_AUTH_AFTER_SIGN_OUT`.
  The sign-in's ID token goes along as `id_token_hint`: Auth signs the browser out at once only for an app that proves
  it asked, and asks the person first otherwise.
- A failed sign-in goes back to `home` with `session('mybeast-auth.error')`, and is reported.
- `MyBeastAuth::users()`: `find($sub)`, `findByEmail()`, `invite($email, $name)`, `block()`, `unblock()`,
  `signOutEverywhere()`, `delete()` - the users API with the server secret, on `MYBEAST_AUTH_ENVIRONMENT`
  (Laravel's `local` is `development`).

Nothing is fetched at boot: the discovery document and the JWKS are read on the first sign-in and cached for an hour
(a key id not in the cached JWKS reads it again once - Auth publishes its next key before it signs).

## Tests

```php
MyBeastAuth::fake()->signInAs(['sub' => 'u-1', 'email' => 'pat@example.test']);   // through your resolver
$this->get('/mybeast-auth/redirect');                                             // comes straight back signed in

MyBeastAuth::fake()->actingAs($user, ['auth_time' => now()->subHour()->timestamp]); // and `fresh` asks again
```

## This repo

```bash
composer install && ./vendor/bin/phpunit && ./vendor/bin/pint
```

## Releasing

Add the version to `CHANGELOG.md`, then tag it: `git tag v0.2.0 && git push --tags`. Packagist reads the tag through
its GitHub hook; there is no version in `composer.json`. The Tests workflow runs on the tag as on every push: PHP 8.2
to 8.4 against Laravel 12 and 13 (Laravel 11 has unfixed advisories, so Composer will not install it).

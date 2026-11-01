<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use MyBeast\Auth\Laravel\Exceptions\SignInFailed;
use MyBeast\Auth\Laravel\Oidc\Provider;
use MyBeast\Auth\Laravel\Users\UsersClient;

/**
 * Signing this app's people in with My Beast Auth. The app says once who a signed-in person is here
 * (resolveUsersWith: find or make your user from the Identity); then GET mybeast-auth.redirect starts a sign-in and
 * the callback ends it - the code for tokens, the ID token checked, your user signed in to the guard, a new session
 * id. The session keeps the Identity (when and how they signed in) for `mybeast-auth.fresh`.
 */
class MyBeastAuth
{
    public const SESSION = 'mybeast-auth';

    private ?Closure $resolver = null;

    /** The ID token of the sign-in being finished, kept for signing out (identityFor sets it). */
    protected ?string $idToken = null;

    public function __construct(
        protected readonly Container $app,
    ) {}

    /** @param  callable(Identity): (Authenticatable|null)  $resolver  null: this person may not sign in to this app */
    public function resolveUsersWith(callable $resolver): void
    {
        $this->resolver = $resolver(...);
    }

    /** A fake takes over the app's resolver (Facades\MyBeastAuth::fake). */
    public function resolveUsersWithFrom(self $other): void
    {
        $this->resolver = $other->resolver;
    }

    /**
     * Where to send the browser to sign in: the provider's /authorize with PKCE, a state and a nonce kept in the
     * session. `$return` is a path of this app (anything else is ignored); `$maxAge` asks for a sign-in at most that
     * many seconds old; `$again` (prompt=login) for a new one whatever the person's session there.
     */
    public function redirectUrl(Request $request, ?string $return = null, ?int $maxAge = null, bool $again = false): string
    {
        $verifier = Str::random(64);
        $state = Str::random(40);
        $nonce = Str::random(40);
        $request->session()->put(self::SESSION.'.pending', [
            'state' => $state,
            'nonce' => $nonce,
            'verifier' => $verifier,
            'return' => self::safeReturn($return),
        ]);

        return $this->provider()->endpoint('authorization_endpoint').'?'.http_build_query(array_filter([
            'response_type' => 'code',
            'client_id' => $this->provider()->clientId(),
            'redirect_uri' => $this->callbackUrl(),
            'scope' => 'openid email profile',
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
            'max_age' => $maxAge,
            'prompt' => $again ? 'login' : null,
            'ui_locales' => $this->app->getLocale(),
        ], fn ($value): bool => $value !== null), '', '&', PHP_QUERY_RFC3986);
    }

    /** The callback: the state checked, the code for an ID token, your user signed in. */
    public function finish(Request $request): RedirectResponse
    {
        $pending = $request->session()->pull(self::SESSION.'.pending');
        $state = (string) $request->query('state');

        if (! is_array($pending) || $state === '' || ! hash_equals((string) ($pending['state'] ?? ''), $state)) {
            throw new SignInFailed('The sign-in came back without this session\'s state.');
        }

        if ($request->query('error') !== null || ! is_string($request->query('code'))) {
            throw new SignInFailed('The sign-in was not finished: '.(string) $request->query('error', 'no code'));
        }

        $identity = $this->identityFor($request->query('code'), (string) $pending['nonce'], (string) $pending['verifier']);
        $user = $this->resolver === null ? null : ($this->resolver)($identity);

        if (! $user instanceof Authenticatable) {
            throw new SignInFailed('This app does not let '.$identity->sub.' in.');
        }

        $this->guard()->login($user);
        $request->session()->regenerate();
        $request->session()->put(self::SESSION.'.identity', $identity->toArray());

        // Auth signs a browser out at once only for the app that proves it asked: this sign-in's own ID token.
        if ($this->idToken !== null) {
            $request->session()->put(self::SESSION.'.id_token', $this->idToken);
        }

        return redirect()->to($pending['return'] ?? (string) config('mybeast-auth.home', '/'));
    }

    /** Who signed in on this session, when and how - null when nobody signed in through Auth. */
    public function identity(?Request $request = null): ?Identity
    {
        $request ??= $this->app->make('request');

        return $request->hasSession() ? Identity::fromArray($request->session()->get(self::SESSION.'.identity')) : null;
    }

    /**
     * Signed out here; then the browser goes to Auth to sign out there too, and comes back. The sign-in's ID token goes
     * along as the proof that this app asked: without it Auth asks the person first (any page can link to sign-out).
     */
    public function signOut(Request $request): RedirectResponse
    {
        $hint = $request->session()->get(self::SESSION.'.id_token');
        $this->guard()->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->away($this->provider()->endpoint('end_session_endpoint').'?'.http_build_query(array_filter([
            'client_id' => $this->provider()->clientId(),
            'post_logout_redirect_uri' => (string) (config('mybeast-auth.after_sign_out') ?? url('/')),
            'id_token_hint' => is_string($hint) ? $hint : null,
        ], fn ($value): bool => $value !== null), '', '&', PHP_QUERY_RFC3986));
    }

    public function users(): UsersClient
    {
        return $this->app->make(UsersClient::class);
    }

    public function provider(): Provider
    {
        return $this->app->make(Provider::class);
    }

    public function callbackUrl(): string
    {
        return route('mybeast-auth.callback');
    }

    protected function identityFor(string $code, string $nonce, string $verifier): Identity
    {
        $tokens = $this->provider()->exchange($code, $this->callbackUrl(), $verifier);
        $identity = Identity::fromClaims($this->provider()->verify($tokens['id_token'], $nonce));
        $this->idToken = $tokens['id_token'];

        return $identity;
    }

    protected function guard(): StatefulGuard
    {
        return $this->app->make('auth')->guard(config('mybeast-auth.guard'));
    }

    /** A path of this app, never another site (no open redirect). */
    protected static function safeReturn(?string $return): ?string
    {
        return $return !== null && str_starts_with($return, '/') && ! str_starts_with($return, '//') && ! str_contains($return, '\\') ? $return : null;
    }
}

<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use MyBeast\Auth\Laravel\Identity;
use MyBeast\Auth\Laravel\MyBeastAuth;

/**
 * MyBeastAuth::fake(): sign-ins without Auth. The redirect comes straight back to the callback, which signs in
 * whoever signInAs() named - through the app's own resolveUsersWith, as a real sign-in would. actingAs() skips even
 * that: the user is signed in with an Identity in the session (for `mybeast-auth.fresh`).
 */
final class MyBeastAuthFake extends MyBeastAuth
{
    private ?Identity $next = null;

    /** @param  Identity|array<string, mixed>  $who  sub, email, … as an ID token would say */
    public function signInAs(Identity|array $who): self
    {
        $this->next = $who instanceof Identity ? $who : Identity::fromClaims($who + ['auth_time' => now()->getTimestamp(), 'amr' => ['pwd'], 'email_verified' => true]);

        return $this;
    }

    public function actingAs(Authenticatable $user, Identity|array|null $who = null): self
    {
        $identity = $who instanceof Identity ? $who : Identity::fromClaims((array) $who + ['sub' => (string) $user->getAuthIdentifier(), 'auth_time' => now()->getTimestamp(), 'amr' => ['pwd'], 'email_verified' => true]);
        $this->guard()->login($user);
        session()->put(self::SESSION.'.identity', $identity->toArray());

        return $this;
    }

    public function redirectUrl(Request $request, ?string $return = null, ?int $maxAge = null, bool $again = false): string
    {
        $state = 'fake-state';
        $request->session()->put(self::SESSION.'.pending', ['state' => $state, 'nonce' => 'fake', 'verifier' => 'fake', 'return' => self::safeReturn($return)]);

        return $this->callbackUrl().'?'.http_build_query(['code' => 'fake-code', 'state' => $state]);
    }

    protected function identityFor(string $code, string $nonce, string $verifier): Identity
    {
        return $this->next ?? throw new \LogicException('MyBeastAuth::fake(): say who signs in with signInAs() first.');
    }
}

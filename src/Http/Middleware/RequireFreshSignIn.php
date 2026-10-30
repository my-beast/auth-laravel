<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use MyBeast\Auth\Laravel\MyBeastAuth;
use Symfony\Component\HttpFoundation\Response;

/**
 * `mybeast-auth.fresh:15` - only for someone who signed in at Auth within the last 15 minutes (their password, a
 * code or a passkey, just now); else to Auth again (max_age) and back here.
 */
final readonly class RequireFreshSignIn
{
    public function __construct(
        private MyBeastAuth $auth,
    ) {}

    public function handle(Request $request, Closure $next, string $minutes = '15'): Response
    {
        $identity = $this->auth->identity($request);
        $seconds = max(1, (int) $minutes) * 60;

        if ($identity === null || $identity->authTime < now()->getTimestamp() - $seconds) {
            $return = $request->isMethod('GET') ? $request->getRequestUri() : null;

            return redirect()->route('mybeast-auth.redirect', array_filter(['return' => $return, 'max_age' => $seconds]));
        }

        return $next($request);
    }
}

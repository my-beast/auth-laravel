<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use MyBeast\Auth\Laravel\Exceptions\SignInFailed;
use MyBeast\Auth\Laravel\MyBeastAuth;

/** GET {prefix}/redirect, GET {prefix}/callback, POST {prefix}/sign-out. */
final class SignInController
{
    public function redirect(Request $request, MyBeastAuth $auth): RedirectResponse
    {
        $maxAge = $request->query('max_age');

        return redirect()->away($auth->redirectUrl(
            $request,
            is_string($request->query('return')) ? $request->query('return') : null,
            is_string($maxAge) && ctype_digit($maxAge) ? (int) $maxAge : null,
            $request->boolean('again'),
        ));
    }

    public function callback(Request $request, MyBeastAuth $auth): RedirectResponse
    {
        try {
            return $auth->finish($request);
        } catch (SignInFailed $failed) {
            report($failed);

            return redirect()->to((string) config('mybeast-auth.home', '/'))->with('mybeast-auth.error', 'Signing in did not work. Please try again.');
        }
    }

    public function signOut(Request $request, MyBeastAuth $auth): RedirectResponse
    {
        return $auth->signOut($request);
    }
}

<?php

declare(strict_types=1);

/*
 * MyBeast Auth: your app's people sign in on Auth's hosted pages; this app gets who they are (an ID token, checked
 * here) and keeps its own users table and its own session. The issuer, the client id and the secret come from the
 * environment's Apps page there (the secret is shown once). Register this app's callback there:
 * {APP_URL}/mybeast-auth/callback (the prefix below).
 */
return [
    // The environment's issuer: https://services.my-beast.com/auth/e/env_… (its Apps page shows it).
    'issuer' => env('MYBEAST_AUTH_ISSUER'),

    'client_id' => env('MYBEAST_AUTH_CLIENT_ID'),
    'client_secret' => env('MYBEAST_AUTH_CLIENT_SECRET'),

    // The routes: GET {prefix}/redirect, GET {prefix}/callback, POST {prefix}/sign-out (names mybeast-auth.*).
    'routes' => [
        'enabled' => true,
        'prefix' => 'mybeast-auth',
        'middleware' => ['web'],
    ],

    // The guard the resolved user is signed in to (null: the app's default), and where they go after.
    'guard' => env('MYBEAST_AUTH_GUARD'),
    'home' => env('MYBEAST_AUTH_HOME', '/'),

    // Where signing out at Auth sends the browser back to (registered on the app's page there). Null: APP_URL.
    'after_sign_out' => env('MYBEAST_AUTH_AFTER_SIGN_OUT'),

    // The users API (find, invite, block, sign out, delete): the product's address and the project's server secret
    // (Settings → Keys there), and the environment it acts on. Laravel's "local" is "development".
    'url' => env('MYBEAST_AUTH_URL'),
    'server_secret' => env('MYBEAST_AUTH_SERVER_SECRET'),
    'environment' => env('MYBEAST_AUTH_ENVIRONMENT', env('APP_ENV', 'production') === 'local' ? 'development' : env('APP_ENV', 'production')),

    // The provider's discovery document and keys are cached this long (an unknown key id reads them again at once).
    'cache_seconds' => (int) env('MYBEAST_AUTH_CACHE_SECONDS', 3600),
    'cache_store' => env('MYBEAST_AUTH_CACHE_STORE'),
    'timeout' => (float) env('MYBEAST_AUTH_TIMEOUT', 5),
];

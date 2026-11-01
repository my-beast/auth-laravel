<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel;

use Illuminate\Http\Client\Factory;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use MyBeast\Auth\Laravel\Http\Controllers\SignInController;
use MyBeast\Auth\Laravel\Http\Middleware\RequireFreshSignIn;
use MyBeast\Auth\Laravel\Oidc\Provider;
use MyBeast\Auth\Laravel\Users\UsersClient;
use RuntimeException;

/**
 * Plugs My Beast Auth in: MyBeastAuth (resolveUsersWith, identity, users), its three routes, and the
 * `mybeast-auth.fresh:{minutes}` middleware. Nothing is fetched at boot: the provider is read on the first sign-in.
 */
final class MyBeastAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/mybeast-auth.php', 'mybeast-auth');

        $this->app->singleton(MyBeastAuth::class, fn ($app): MyBeastAuth => new MyBeastAuth($app));

        $this->app->bind(Provider::class, function ($app): Provider {
            $config = (array) $app['config']->get('mybeast-auth', []);
            $issuer = rtrim((string) ($config['issuer'] ?? ''), '/');

            if ($issuer === '' || ($config['client_id'] ?? '') === '' || ($config['client_secret'] ?? '') === '') {
                throw new RuntimeException('Set MYBEAST_AUTH_ISSUER, MYBEAST_AUTH_CLIENT_ID and MYBEAST_AUTH_CLIENT_SECRET (the app\'s page at Auth).');
            }

            return new Provider(
                $app->make(Factory::class),
                $app['cache']->store($config['cache_store'] ?? null),
                $issuer,
                (string) $config['client_id'],
                (string) $config['client_secret'],
                max(60, (int) ($config['cache_seconds'] ?? 3600)),
                max(0.5, (float) ($config['timeout'] ?? 5)),
            );
        });

        $this->app->bind(UsersClient::class, fn ($app): UsersClient => new UsersClient(
            $app->make(Factory::class),
            (string) $app['config']->get('mybeast-auth.url', ''),
            (string) $app['config']->get('mybeast-auth.server_secret', ''),
            (string) $app['config']->get('mybeast-auth.environment', 'production'),
            max(0.5, (float) $app['config']->get('mybeast-auth.timeout', 5)),
        ));
    }

    public function boot(Router $router): void
    {
        $this->publishes([__DIR__.'/../config/mybeast-auth.php' => config_path('mybeast-auth.php')], 'mybeast-auth-config');
        $router->aliasMiddleware('mybeast-auth.fresh', RequireFreshSignIn::class);

        $routes = (array) config('mybeast-auth.routes', []);

        if (($routes['enabled'] ?? true) === true) {
            $router->middleware((array) ($routes['middleware'] ?? ['web']))
                ->prefix((string) ($routes['prefix'] ?? 'mybeast-auth'))
                ->name('mybeast-auth.')
                ->group(function () use ($router): void {
                    $router->get('redirect', [SignInController::class, 'redirect'])->name('redirect');
                    $router->get('callback', [SignInController::class, 'callback'])->name('callback');
                    $router->post('sign-out', [SignInController::class, 'signOut'])->name('sign-out');
                });
        }
    }
}

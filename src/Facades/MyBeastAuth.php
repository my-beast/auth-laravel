<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel\Facades;

use Illuminate\Support\Facades\Facade;
use MyBeast\Auth\Laravel\MyBeastAuth as Manager;
use MyBeast\Auth\Laravel\Testing\MyBeastAuthFake;

/**
 * @method static void resolveUsersWith(callable $resolver)
 * @method static \MyBeast\Auth\Laravel\Identity|null identity(?\Illuminate\Http\Request $request = null)
 * @method static \MyBeast\Auth\Laravel\Users\UsersClient users()
 * @method static string redirectUrl(\Illuminate\Http\Request $request, ?string $return = null, ?int $maxAge = null, bool $again = false)
 *
 * @see Manager
 */
final class MyBeastAuth extends Facade
{
    /** Sign-ins without Auth, for tests: signInAs(), actingAs(). The app's resolver is kept. */
    public static function fake(): MyBeastAuthFake
    {
        $fake = new MyBeastAuthFake(self::getFacadeApplication());
        $real = self::getFacadeApplication()->make(Manager::class);
        $fake->resolveUsersWithFrom($real);
        self::swap($fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return Manager::class;
    }
}

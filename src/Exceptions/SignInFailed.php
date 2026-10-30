<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel\Exceptions;

use RuntimeException;

/** The sign-in did not come back as one: a wrong state, a token that does not check out, the app saying no. */
final class SignInFailed extends RuntimeException {}

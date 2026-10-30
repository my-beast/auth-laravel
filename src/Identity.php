<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel;

/**
 * Who signed in, as Auth's ID token says: `sub` is the person's id in the environment (store it on your user), the
 * address and whether Auth proved it, when they signed in and how (`amr`: pwd, otp, hwk for a passkey, fed for
 * Google/Microsoft/Apple, mfa when two factors were used).
 */
final readonly class Identity
{
    /**
     * @param  list<string>  $amr
     * @param  array<string, mixed>  $claims
     */
    public function __construct(
        public string $sub,
        public ?string $email,
        public bool $emailVerified,
        public ?string $name,
        public int $authTime,
        public array $amr,
        public ?string $sid = null,
        public array $claims = [],
    ) {}

    /** @param  array<string, mixed>  $claims */
    public static function fromClaims(array $claims): self
    {
        return new self(
            sub: (string) $claims['sub'],
            email: isset($claims['email']) ? (string) $claims['email'] : null,
            emailVerified: ($claims['email_verified'] ?? false) === true,
            name: isset($claims['name']) ? (string) $claims['name'] : null,
            authTime: (int) ($claims['auth_time'] ?? $claims['iat'] ?? 0),
            amr: array_values(array_map('strval', (array) ($claims['amr'] ?? []))),
            sid: isset($claims['sid']) ? (string) $claims['sid'] : null,
            claims: $claims,
        );
    }

    public function usedTwoFactors(): bool
    {
        return in_array('mfa', $this->amr, true);
    }

    /** @return array<string, mixed> what the session keeps */
    public function toArray(): array
    {
        return [
            'sub' => $this->sub,
            'email' => $this->email,
            'email_verified' => $this->emailVerified,
            'name' => $this->name,
            'auth_time' => $this->authTime,
            'amr' => $this->amr,
            'sid' => $this->sid,
        ];
    }

    /** @param  array<string, mixed>|null  $data */
    public static function fromArray(?array $data): ?self
    {
        return is_array($data) && is_string($data['sub'] ?? null) ? self::fromClaims($data) : null;
    }
}

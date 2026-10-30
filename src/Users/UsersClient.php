<?php

declare(strict_types=1);

namespace MyBeast\Auth\Laravel\Users;

use Illuminate\Http\Client\Factory as Http;
use Illuminate\Http\Client\PendingRequest;
use RuntimeException;

/**
 * The users API, from this app's server: the people of its environment, by id (`sub`) or address. Each call takes the
 * project's server secret (MYBEAST_AUTH_SERVER_SECRET); every change is in Auth's audit log as this secret's.
 */
final readonly class UsersClient
{
    public function __construct(
        private Http $http,
        private string $url,
        private string $secret,
        private string $environment,
        private float $timeout,
    ) {}

    /** @return array<string, mixed>|null */
    public function find(string $sub): ?array
    {
        $response = $this->request()->get($this->base().'/users/'.rawurlencode($sub));

        return $response->status() === 404 ? null : $response->throw()->json();
    }

    /** @return array<string, mixed>|null */
    public function findByEmail(string $email): ?array
    {
        $response = $this->request()->get($this->base().'/users', ['email' => $email]);

        return $response->status() === 404 ? null : $response->throw()->json();
    }

    /**
     * A person made with the address and invited (the e-mail goes from Auth unless $send is false).
     *
     * @return array<string, mixed>
     */
    public function invite(string $email, ?string $name = null, bool $send = true): array
    {
        return $this->request()->post($this->base().'/users', ['email' => $email, 'name' => $name, 'send_invitation' => $send])->throw()->json();
    }

    /** @return array<string, mixed> */
    public function block(string $sub): array
    {
        return $this->request()->post($this->base().'/users/'.rawurlencode($sub).'/block')->throw()->json();
    }

    /** @return array<string, mixed> */
    public function unblock(string $sub): array
    {
        return $this->request()->post($this->base().'/users/'.rawurlencode($sub).'/unblock')->throw()->json();
    }

    /** @return int how many devices were signed out */
    public function signOutEverywhere(string $sub): int
    {
        return (int) $this->request()->post($this->base().'/users/'.rawurlencode($sub).'/sign-out')->throw()->json('signed_out_devices');
    }

    public function delete(string $sub): void
    {
        $this->request()->delete($this->base().'/users/'.rawurlencode($sub))->throw();
    }

    private function request(): PendingRequest
    {
        if ($this->url === '' || $this->secret === '') {
            throw new RuntimeException('Set MYBEAST_AUTH_URL and MYBEAST_AUTH_SERVER_SECRET to use the users API.');
        }

        return $this->http->acceptJson()->asJson()->withToken($this->secret)->timeout($this->timeout);
    }

    private function base(): string
    {
        return rtrim($this->url, '/').'/api/v1/environments/'.rawurlencode($this->environment);
    }
}

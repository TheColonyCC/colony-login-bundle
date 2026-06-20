<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Security;

/**
 * Whether "Log in with the Colony" is configured. The integration is dormant
 * (routes 404, button hidden) until both a client id and secret are present, so
 * an app can ship the bundle before credentials are provisioned.
 */
final class ColonyLoginState
{
    public function __construct(
        private readonly string $clientId,
        private readonly string $clientSecret,
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->clientId !== '' && $this->clientSecret !== '';
    }
}

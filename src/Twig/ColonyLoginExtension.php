<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Twig;

use TheColony\ColonyLoginBundle\Security\ColonyLoginState;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * Exposes `colony_login_enabled()` so templates render the "Log in with the
 * Colony" button only when the integration is configured.
 */
final class ColonyLoginExtension extends AbstractExtension
{
    public function __construct(private readonly ColonyLoginState $state)
    {
    }

    /** @return list<TwigFunction> */
    public function getFunctions(): array
    {
        return [new TwigFunction('colony_login_enabled', $this->enabled(...))];
    }

    public function enabled(): bool
    {
        return $this->state->isEnabled();
    }
}

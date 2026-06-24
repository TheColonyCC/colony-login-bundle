<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Twig;

use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use TheColony\ColonyLoginBundle\Security\ColonyLoginState;
use TheColony\OAuth2\ColonyBrand;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/**
 * Twig helpers for "Log in with the Colony".
 *
 * - `colony_login_enabled()` — is the integration configured?
 * - `colony_login_button(options = {})` — the branded, accessible login button.
 *   Self-hides (renders nothing) while the integration is unconfigured, so you
 *   can drop it straight into a template without an `{% if %}` guard.
 * - `colony_login_styles()` — a `<style>` block for the button (include once).
 * - `colony_mark(variant, size)` — just the Colony mark as inline SVG.
 *
 * The button/mark markup comes from {@see ColonyBrand} in `thecolony/oauth2-colony`,
 * so the Symfony button matches the PHP and Python SDKs exactly.
 */
final class ColonyLoginExtension extends AbstractExtension
{
    public function __construct(
        private readonly ColonyLoginState $state,
        private readonly ?UrlGeneratorInterface $urlGenerator = null,
    ) {
    }

    /** @return list<TwigFunction> */
    public function getFunctions(): array
    {
        $html = ['is_safe' => ['html']];

        return [
            new TwigFunction('colony_login_enabled', $this->enabled(...)),
            new TwigFunction('colony_login_button', $this->loginButton(...), $html),
            new TwigFunction('colony_login_styles', $this->loginStyles(...), $html),
            new TwigFunction('colony_mark', $this->mark(...), $html),
        ];
    }

    public function enabled(): bool
    {
        return $this->state->isEnabled();
    }

    /**
     * The "Log in with the Colony" button.
     *
     * Renders nothing while the integration is unconfigured (the login route
     * 404s then, so a visible button would dead-link). By default the button
     * points at the bundle's `colony_login` start route; override with `href`
     * (absolute URL) or `route` (a different route name). All other options are
     * forwarded to {@see ColonyBrand::loginButton()} — `label`, `theme`
     * (`auto`/`light`/`dark`), `variant`, `size`, `class`, `attributes`.
     *
     * @param array<string, mixed> $options
     */
    public function loginButton(array $options = []): string
    {
        if (!$this->state->isEnabled()) {
            return '';
        }

        $href = isset($options['href']) ? (string) $options['href'] : null;
        $route = isset($options['route']) ? (string) $options['route'] : 'colony_login';
        unset($options['href'], $options['route']);

        if ($href === null) {
            if ($this->urlGenerator === null) {
                throw new \LogicException(
                    'colony_login_button() needs the router to build the login URL. '
                    . 'Pass an explicit href, or ensure symfony/routing is available.'
                );
            }
            $href = $this->urlGenerator->generate($route);
        }

        /** @var array{label?: string, theme?: string, variant?: string, size?: int, class?: string, attributes?: array<string, string|int|bool>} $options */
        return ColonyBrand::loginButton($href, $options);
    }

    /** A `<style>` block with the default button stylesheet; include once per page. */
    public function loginStyles(): string
    {
        return '<style>' . ColonyBrand::buttonStylesheet() . '</style>';
    }

    /** The Colony mark as inline SVG (see {@see ColonyBrand::mark()} for variants). */
    public function mark(string $variant = ColonyBrand::CURRENT, int $size = 24): string
    {
        return ColonyBrand::mark($variant, $size);
    }
}

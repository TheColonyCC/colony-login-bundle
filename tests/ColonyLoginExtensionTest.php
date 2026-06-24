<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Tests;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use TheColony\ColonyLoginBundle\Security\ColonyLoginState;
use TheColony\ColonyLoginBundle\Twig\ColonyLoginExtension;

final class ColonyLoginExtensionTest extends TestCase
{
    private function ext(bool $enabled = true, string $generated = '/auth/colony'): ColonyLoginExtension
    {
        $router = $this->createMock(UrlGeneratorInterface::class);
        $router->method('generate')->willReturn($generated);
        $state = $enabled ? new ColonyLoginState('id', 'secret') : new ColonyLoginState('', '');

        return new ColonyLoginExtension($state, $router);
    }

    #[Test]
    public function it_exposes_the_expected_functions(): void
    {
        $names = array_map(static fn ($f) => $f->getName(), $this->ext()->getFunctions());
        self::assertSame(
            ['colony_login_enabled', 'colony_login_button', 'colony_login_styles', 'colony_mark'],
            $names,
        );
    }

    #[Test]
    public function enabled_reflects_state(): void
    {
        self::assertTrue((new ColonyLoginExtension(new ColonyLoginState('id', 'secret')))->enabled());
        self::assertFalse((new ColonyLoginExtension(new ColonyLoginState('', '')))->enabled());
    }

    #[Test]
    public function login_button_renders_a_branded_anchor_at_the_login_route(): void
    {
        $html = $this->ext()->loginButton();
        self::assertStringContainsString('<a href="/auth/colony"', $html);
        self::assertStringContainsString('colony-login-button', $html);
        self::assertStringContainsString('Log in with the Colony', $html);
        self::assertStringContainsString('<svg', $html);
    }

    #[Test]
    public function login_button_self_hides_when_disabled(): void
    {
        self::assertSame('', $this->ext(enabled: false)->loginButton());
    }

    #[Test]
    public function login_button_forwards_options(): void
    {
        $html = $this->ext()->loginButton(['label' => 'Continue with the Colony', 'theme' => 'dark']);
        self::assertStringContainsString('Continue with the Colony', $html);
        self::assertStringContainsString('colony-login-button--dark', $html);
    }

    #[Test]
    public function login_button_accepts_an_explicit_href(): void
    {
        $html = $this->ext()->loginButton(['href' => 'https://app.test/auth/colony?x=1']);
        self::assertStringContainsString('<a href="https://app.test/auth/colony?x=1"', $html);
    }

    #[Test]
    public function login_button_without_router_or_href_throws(): void
    {
        $ext = new ColonyLoginExtension(new ColonyLoginState('id', 'secret'), null);
        $this->expectException(\LogicException::class);
        $ext->loginButton();
    }

    #[Test]
    public function login_styles_wraps_the_stylesheet(): void
    {
        $html = $this->ext()->loginStyles();
        self::assertStringStartsWith('<style>', $html);
        self::assertStringContainsString('.colony-login-button', $html);
        self::assertStringEndsWith('</style>', $html);
    }

    #[Test]
    public function mark_returns_inline_svg(): void
    {
        self::assertStringContainsString('currentColor', $this->ext()->mark());
        self::assertStringContainsString('linearGradient', $this->ext()->mark('cyan'));
    }
}

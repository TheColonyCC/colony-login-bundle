<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Tests;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TheColony\ColonyLoginBundle\Security\ColonyLoginState;
use TheColony\ColonyLoginBundle\Twig\ColonyLoginExtension;

final class ColonyLoginExtensionTest extends TestCase
{
    #[Test]
    public function it_exposes_the_colony_login_enabled_function(): void
    {
        $ext = new ColonyLoginExtension(new ColonyLoginState('id', 'secret'));
        $functions = $ext->getFunctions();
        self::assertCount(1, $functions);
        self::assertSame('colony_login_enabled', $functions[0]->getName());
    }

    #[Test]
    public function enabled_reflects_state(): void
    {
        self::assertTrue((new ColonyLoginExtension(new ColonyLoginState('id', 'secret')))->enabled());
        self::assertFalse((new ColonyLoginExtension(new ColonyLoginState('', '')))->enabled());
    }
}

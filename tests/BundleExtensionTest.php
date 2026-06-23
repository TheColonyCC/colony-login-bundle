<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Tests;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use TheColony\ColonyLoginBundle\ColonyLoginBundle;
use TheColony\ColonyLoginBundle\Controller\ColonyLoginController;
use TheColony\ColonyLoginBundle\Security\ColonyUserProvisionerInterface;
use TheColony\OAuth2\ColonyProvider;

final class BundleExtensionTest extends TestCase
{
    /** @param array<string,mixed> $config */
    private function load(array $config): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.debug', true);
        $container->setParameter('kernel.build_dir', sys_get_temp_dir());
        $container->setParameter('kernel.project_dir', sys_get_temp_dir());
        $extension = (new ColonyLoginBundle())->getContainerExtension();
        self::assertNotNull($extension);
        $extension->load([$config], $container);

        return $container;
    }

    #[Test]
    public function it_registers_the_core_services_with_defaults(): void
    {
        $c = $this->load(['provisioner' => 'app.provisioner']);

        self::assertTrue($c->hasDefinition('colony_login.provider'));
        self::assertTrue($c->hasDefinition('colony_login.state'));
        self::assertTrue($c->hasDefinition(ColonyLoginController::class));
        self::assertTrue($c->hasDefinition('colony_login.twig_extension'));

        $provider = $c->getDefinition('colony_login.provider');
        self::assertSame(ColonyProvider::class, $provider->getClass());
        self::assertTrue($provider->isPublic(), 'provider is public so apps/tests can reach it');
        $options = $provider->getArgument(0);
        self::assertSame('https://thecolony.cc', $options['issuer']);
        self::assertSame('openid profile email', $options['scope']);
        self::assertArrayNotHasKey('cache', $options, 'no cache option when none configured');

        // provisioner alias points at the app service
        $alias = $c->getAlias(ColonyUserProvisionerInterface::class);
        self::assertSame('app.provisioner', (string) $alias);
    }

    #[Test]
    public function controller_is_public_and_wired(): void
    {
        $c = $this->load(['provisioner' => 'app.provisioner']);
        $def = $c->getDefinition(ColonyLoginController::class);
        self::assertTrue($def->isPublic());
        self::assertSame(ColonyLoginController::class, $def->getClass(), 'explicit class so passes can reflect it');
        // MUST be autowired + autoconfigured so AutowireRequiredMethodsPass injects the
        // AbstractController service-subscriber container via #[Required] setContainer();
        // otherwise the route resolver throws "controller has no container set".
        self::assertTrue($def->isAutowired(), 'controller must be autowired for setContainer injection');
        self::assertTrue($def->isAutoconfigured(), 'controller must be autoconfigured');
        self::assertTrue(
            $c->getDefinition('colony_login.twig_extension')->isAutoconfigured(),
            'twig extension must be autoconfigured for the twig.extension tag',
        );

        $args = $def->getArguments();
        self::assertEquals(new Reference('colony_login.provider'), $args[0]);
        self::assertEquals(new Reference(ColonyUserProvisionerInterface::class), $args[1]);
        self::assertEquals(new Reference('security.helper'), $args[3]);
        self::assertSame('app_dashboard', $args[4]); // default success route
        self::assertSame('app_login', $args[5]);     // default failure route
    }

    #[Test]
    public function cache_option_wires_a_psr16_wrapper(): void
    {
        $c = $this->load(['provisioner' => 'app.provisioner', 'cache' => 'cache.app']);
        self::assertTrue($c->hasDefinition('colony_login.psr16_cache'));
        $wrapper = $c->getDefinition('colony_login.psr16_cache');
        self::assertEquals(new Reference('cache.app'), $wrapper->getArgument(0));

        $options = $c->getDefinition('colony_login.provider')->getArgument(0);
        self::assertEquals(new Reference('colony_login.psr16_cache'), $options['cache']);
    }

    #[Test]
    public function custom_routes_and_authenticator_flow_through(): void
    {
        $c = $this->load([
            'provisioner' => 'app.provisioner',
            'authenticator' => 'form_login',
            'default_uri' => 'https://app.example',
            'routes' => ['success' => 'home', 'failure' => 'signin'],
        ]);
        $args = $c->getDefinition(ColonyLoginController::class)->getArguments();
        self::assertSame('home', $args[4]);
        self::assertSame('signin', $args[5]);
        self::assertSame('form_login', $args[6]);
        self::assertSame('https://app.example', $args[7]);
    }

    #[Test]
    public function client_credentials_flow_to_state_and_provider(): void
    {
        $c = $this->load([
            'provisioner' => 'app.provisioner',
            'client_id' => 'cid',
            'client_secret' => 'csecret',
            'scope' => 'openid',
        ]);
        self::assertSame(['cid', 'csecret'], $c->getDefinition('colony_login.state')->getArguments());
        $options = $c->getDefinition('colony_login.provider')->getArgument(0);
        self::assertSame('cid', $options['clientId']);
        self::assertSame('openid', $options['scope']);
    }

    #[Test]
    public function provisioner_is_required(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->load([]);
    }

    #[Test]
    public function defaults_to_client_secret_post_without_private_key_options(): void
    {
        $options = $this->load(['provisioner' => 'app.provisioner'])
            ->getDefinition('colony_login.provider')->getArgument(0);
        self::assertSame('client_secret_post', $options['tokenEndpointAuthMethod']);
        self::assertSame('RS256', $options['signingAlg']);
        self::assertFalse($options['usePar']);
        self::assertArrayNotHasKey('privateKey', $options);
        self::assertArrayNotHasKey('privateKeyId', $options);
    }

    #[Test]
    public function private_key_jwt_options_flow_to_the_provider(): void
    {
        $options = $this->load([
            'provisioner' => 'app.provisioner',
            'client_id' => 'cid',
            'token_endpoint_auth_method' => 'private_key_jwt',
            'private_key' => "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----",
            'private_key_id' => 'key-1',
            'signing_alg' => 'ES256',
        ])->getDefinition('colony_login.provider')->getArgument(0);
        self::assertSame('private_key_jwt', $options['tokenEndpointAuthMethod']);
        self::assertStringContainsString('BEGIN PRIVATE KEY', $options['privateKey']);
        self::assertSame('key-1', $options['privateKeyId']);
        self::assertSame('ES256', $options['signingAlg']);
    }

    #[Test]
    public function use_par_flows_to_the_provider(): void
    {
        $options = $this->load(['provisioner' => 'app.provisioner', 'use_par' => true])
            ->getDefinition('colony_login.provider')->getArgument(0);
        self::assertTrue($options['usePar']);
    }

    #[Test]
    public function backchannel_logout_handler_is_aliased_and_passed_when_configured(): void
    {
        $c = $this->load([
            'provisioner' => 'app.provisioner',
            'backchannel_logout_handler' => 'app.logout_handler',
        ]);
        $alias = $c->getAlias(\TheColony\ColonyLoginBundle\Security\ColonyBackchannelLogoutHandlerInterface::class);
        self::assertSame('app.logout_handler', (string) $alias);
        // the controller receives the handler service as its 9th argument (index 8)
        $args = $c->getDefinition(ColonyLoginController::class)->getArguments();
        self::assertInstanceOf(Reference::class, $args[8]);
    }

    #[Test]
    public function controller_gets_null_logout_handler_when_unconfigured(): void
    {
        $c = $this->load(['provisioner' => 'app.provisioner']);
        self::assertFalse($c->hasAlias(\TheColony\ColonyLoginBundle\Security\ColonyBackchannelLogoutHandlerInterface::class));
        $args = $c->getDefinition(ColonyLoginController::class)->getArguments();
        self::assertNull($args[8]);
    }
}

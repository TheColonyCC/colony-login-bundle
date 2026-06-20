<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle;

use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use TheColony\ColonyLoginBundle\Controller\ColonyLoginController;
use TheColony\ColonyLoginBundle\Security\ColonyLoginState;
use TheColony\ColonyLoginBundle\Security\ColonyUserProvisionerInterface;
use TheColony\ColonyLoginBundle\Twig\ColonyLoginExtension;
use TheColony\OAuth2\ColonyProvider;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * "Log in with the Colony" Symfony bundle.
 *
 * Register the bundle, point `colony_login.provisioner` at your
 * {@see ColonyUserProvisionerInterface} implementation, import the controller
 * routes, and add the button (`{% if colony_login_enabled() %}`). See README.
 */
final class ColonyLoginBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        // @phpstan-ignore-next-line — fluent config builder
        $definition->rootNode()
            ->children()
                ->scalarNode('client_id')->defaultValue('')->info('Colony OAuth client id (env placeholder is fine)')->end()
                ->scalarNode('client_secret')->defaultValue('')->info('Colony OAuth client secret')->end()
                ->scalarNode('issuer')->defaultValue('https://thecolony.cc')->cannotBeEmpty()->end()
                ->scalarNode('scope')->defaultValue('openid profile email')->cannotBeEmpty()->end()
                ->scalarNode('default_uri')->defaultValue('')->info('Canonical app origin (e.g. https://app.example) — flow is pinned here so redirect_uri matches and the session survives')->end()
                ->scalarNode('provisioner')->isRequired()->cannotBeEmpty()->info('Service id implementing ColonyUserProvisionerInterface')->end()
                ->scalarNode('cache')->defaultValue('')->info('PSR-6 cache pool service id for discovery + JWKS (e.g. cache.app)')->end()
                ->scalarNode('authenticator')->defaultValue('')->info('Authenticator name passed to Security::login() (e.g. form_login)')->end()
                ->arrayNode('routes')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('success')->defaultValue('app_dashboard')->info('Route to redirect to after a successful login')->end()
                        ->scalarNode('failure')->defaultValue('app_login')->info('Route to redirect to on cancellation or error')->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * @param array{
     *     client_id: string, client_secret: string, issuer: string, scope: string,
     *     default_uri: string, provisioner: string, cache: string, authenticator: string,
     *     routes: array{success: string, failure: string}
     * } $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $services = $container->services();
        // autoconfigure so the AbstractController controller gets its service-subscriber
        // container (setContainer) + controller.service_arguments tag, and the Twig
        // extension gets the twig.extension tag.
        $services->defaults()->autoconfigure();

        $services->set('colony_login.state', ColonyLoginState::class)
            ->args([$config['client_id'], $config['client_secret']])
            ->public(); // readable by apps; swappable in tests

        $providerOptions = [
            'clientId' => $config['client_id'],
            'clientSecret' => $config['client_secret'],
            'issuer' => $config['issuer'],
            'scope' => $config['scope'],
        ];
        if ($config['cache'] !== '') {
            $services->set('colony_login.psr16_cache', Psr16Cache::class)
                ->args([service($config['cache'])]);
            $providerOptions['cache'] = service('colony_login.psr16_cache');
        }

        $services->set('colony_login.provider', ColonyProvider::class)
            ->args([$providerOptions, []])
            ->public(); // so apps can reach it directly (e.g. verifyIdToken) and tests can swap it

        // Registered under its FQCN so Symfony's controller resolver finds it by
        // the class name used in the route attributes. Must be autowired with an
        // explicit class so AutowireRequiredMethodsPass injects the AbstractController
        // service-subscriber container via its #[Required] setContainer().
        $services->set(ColonyLoginController::class, ColonyLoginController::class)
            ->autowire()
            ->public()
            ->args([
                service('colony_login.provider'),
                service(ColonyUserProvisionerInterface::class),
                service('colony_login.state'),
                service('security.helper'),
                $config['routes']['success'],
                $config['routes']['failure'],
                $config['authenticator'],
                $config['default_uri'],
            ]);

        $services->set('colony_login.twig_extension', ColonyLoginExtension::class)
            ->args([service('colony_login.state')]);

        // The app's provisioner, exposed under the interface the controller needs.
        $services->alias(ColonyUserProvisionerInterface::class, $config['provisioner']);
    }
}

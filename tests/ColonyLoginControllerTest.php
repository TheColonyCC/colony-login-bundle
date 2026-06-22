<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use TheColony\ColonyLoginBundle\Controller\ColonyLoginController;
use TheColony\ColonyLoginBundle\Security\ColonyBackchannelLogoutHandlerInterface;
use TheColony\ColonyLoginBundle\Security\ColonyLoginState;
use TheColony\ColonyLoginBundle\Security\ColonyUserProvisionerInterface;
use TheColony\OAuth2\ColonyProvider;

final class ColonyLoginControllerTest extends TestCase
{
    private const DISCOVERY = [
        'issuer' => 'https://thecolony.cc',
        'authorization_endpoint' => 'https://thecolony.cc/oauth/authorize',
        'token_endpoint' => 'https://thecolony.cc/oauth/token',
        'userinfo_endpoint' => 'https://thecolony.cc/oauth/userinfo',
        'jwks_uri' => 'https://thecolony.cc/.well-known/jwks.json',
    ];

    private const BCL = 'http://schemas.openid.net/event/backchannel-logout';

    private Session $session;
    private TokenStorage $tokenStorage;

    private function discovery(): GuzzleResponse
    {
        return new GuzzleResponse(200, [], (string) json_encode(self::DISCOVERY));
    }

    /** @param list<GuzzleResponse> $responses */
    private function provider(array $responses, bool $enabledCreds = true): ColonyProvider
    {
        $client = new Client(['handler' => HandlerStack::create(new MockHandler($responses))]);

        return new ColonyProvider([
            'clientId' => $enabledCreds ? 'client_abc' : '',
            'clientSecret' => $enabledCreds ? 'secret' : '',
            'issuer' => 'https://thecolony.cc',
        ], ['httpClient' => $client]);
    }

    /** @param list<GuzzleResponse> $responses */
    private function controller(
        array $responses = [],
        bool $enabled = true,
        string $defaultUri = '',
        ?UserInterface $provisioned = null,
        ?ColonyBackchannelLogoutHandlerInterface $logoutHandler = null,
    ): ColonyLoginController {
        $this->session = new Session(new MockArraySessionStorage());
        $this->tokenStorage = new TokenStorage();

        $request = new Request();
        $request->setSession($this->session);
        $requestStack = new RequestStack();
        $requestStack->push($request);

        $router = new class implements UrlGeneratorInterface {
            public function generate(string $name, array $parameters = [], int $referenceType = self::ABSOLUTE_PATH): string
            {
                return '/'.$name;
            }

            public function setContext(RequestContext $context): void
            {
            }

            public function getContext(): RequestContext
            {
                return new RequestContext();
            }
        };

        $container = new Container();
        $container->set('router', $router);
        $container->set('request_stack', $requestStack);
        $container->set('security.token_storage', $this->tokenStorage);

        $provisioner = new class($provisioned) implements ColonyUserProvisionerInterface {
            public bool $called = false;

            public function __construct(private readonly ?UserInterface $user)
            {
            }

            public function provision(array $claims): UserInterface
            {
                $this->called = true;

                return $this->user ?? new InMemoryUser('colonist-one', null, ['ROLE_USER']);
            }
        };

        $state = new ColonyLoginState($enabled ? 'client_abc' : '', $enabled ? 'secret' : '');

        $controller = new ColonyLoginController(
            $this->provider($responses, $enabled),
            $provisioner,
            $state,
            new Security(new Container()), // never invoked on the paths under test
            'app_dashboard',
            'app_login',
            'form_login',
            $defaultUri,
            $logoutHandler,
        );
        $controller->setContainer($container);

        return $controller;
    }

    #[Test]
    public function start_404s_when_disabled(): void
    {
        $controller = $this->controller(enabled: false);
        $this->expectException(NotFoundHttpException::class);
        $controller->start(new Request());
    }

    #[Test]
    public function start_redirects_to_authorize_and_stores_session(): void
    {
        $controller = $this->controller([$this->discovery()]);
        $request = new Request();
        $request->setSession($this->session);

        $response = $controller->start($request);
        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringStartsWith('https://thecolony.cc/oauth/authorize?', $response->getTargetUrl());

        parse_str((string) parse_url($response->getTargetUrl(), PHP_URL_QUERY), $q);
        self::assertSame($this->session->get('colony_oidc_state'), $q['state']);
        self::assertSame($this->session->get('colony_oidc_nonce'), $q['nonce']);
        self::assertNotEmpty($this->session->get('colony_oidc_pkce'));
        self::assertSame('S256', $q['code_challenge_method']);
    }

    #[Test]
    public function start_redirects_logged_in_user_to_success(): void
    {
        $controller = $this->controller([$this->discovery()]);
        $this->tokenStorage->setToken(new UsernamePasswordToken(new InMemoryUser('x', null), 'main', ['ROLE_USER']));
        $request = new Request();
        $request->setSession($this->session);

        $response = $controller->start($request);
        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/app_dashboard', $response->getTargetUrl());
    }

    #[Test]
    public function start_on_canonical_host_builds_origin_redirect_uri(): void
    {
        $controller = $this->controller([$this->discovery()], defaultUri: 'https://app.example');
        $request = Request::create('https://app.example/auth/colony');
        $request->setSession($this->session);

        $response = $controller->start($request);
        parse_str((string) parse_url($response->getTargetUrl(), PHP_URL_QUERY), $q);
        self::assertSame('https://app.example/colony_login_callback', $q['redirect_uri']);
    }

    #[Test]
    public function start_bounces_to_canonical_host(): void
    {
        $controller = $this->controller([], defaultUri: 'https://app.example');
        $request = Request::create('https://www.app.example/auth/colony');
        $request->setSession($this->session);

        $response = $controller->start($request);
        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('https://app.example/auth/colony', $response->getTargetUrl());
    }

    #[Test]
    public function callback_404s_when_disabled(): void
    {
        $controller = $this->controller(enabled: false);
        $this->expectException(NotFoundHttpException::class);
        $controller->callback(new Request());
    }

    #[Test]
    public function callback_cancelled_redirects_to_failure(): void
    {
        $controller = $this->controller();
        $request = new Request(['error' => 'access_denied']);
        $request->setSession($this->session);

        $response = $controller->callback($request);
        self::assertSame('/app_login', $response->getTargetUrl());
    }

    #[Test]
    public function callback_with_bad_state_redirects_to_failure(): void
    {
        $controller = $this->controller();
        $this->session->set('colony_oidc_state', 'expected');
        $request = new Request(['code' => 'abc', 'state' => 'tampered']);
        $request->setSession($this->session);

        $response = $controller->callback($request);
        self::assertSame('/app_login', $response->getTargetUrl());
        self::assertNull($this->session->get('colony_oidc_state'), 'one-time state is cleared');
    }

    #[Test]
    public function callback_with_oidc_failure_redirects_to_failure(): void
    {
        $errBody = (string) json_encode(['error' => 'invalid_grant']);
        $controller = $this->controller([
            $this->discovery(),
            new GuzzleResponse(400, ['Content-Type' => 'application/json'], $errBody),
        ]);
        $this->session->set('colony_oidc_state', 'good-state');
        $this->session->set('colony_oidc_nonce', 'the-nonce');
        $this->session->set('colony_oidc_pkce', 'verifier');
        $request = new Request(['code' => 'abc', 'state' => 'good-state']);
        $request->setSession($this->session);

        $response = $controller->callback($request);
        self::assertSame('/app_login', $response->getTargetUrl());
    }

    // -- silent SSO ----------------------------------------------------------

    #[Test]
    public function silent_redirects_with_prompt_none(): void
    {
        $controller = $this->controller([$this->discovery()]);
        $request = new Request();
        $request->setSession($this->session);

        $response = $controller->silent($request);
        self::assertInstanceOf(RedirectResponse::class, $response);
        parse_str((string) parse_url($response->getTargetUrl(), PHP_URL_QUERY), $q);
        self::assertSame('none', $q['prompt']);
        self::assertNotEmpty($this->session->get('colony_oidc_state'));
    }

    // -- back-channel logout -------------------------------------------------

    private function logoutHandler(): ColonyBackchannelLogoutHandlerInterface
    {
        return new class implements ColonyBackchannelLogoutHandlerInterface {
            /** @var array<string,mixed>|null */
            public ?array $claims = null;

            public function logout(array $claims): void
            {
                $this->claims = $claims;
            }
        };
    }

    #[Test]
    public function backchannel_404s_when_no_handler_configured(): void
    {
        $controller = $this->controller([]);   // no logout handler
        $this->expectException(NotFoundHttpException::class);
        $controller->backchannelLogout(new Request());
    }

    #[Test]
    public function backchannel_400s_on_missing_token(): void
    {
        $controller = $this->controller([], logoutHandler: $this->logoutHandler());
        $response = $controller->backchannelLogout(new Request());
        self::assertSame(400, $response->getStatusCode());
    }

    #[Test]
    public function backchannel_400s_on_invalid_token(): void
    {
        $kit = new OidcTestKit();
        $other = new OidcTestKit();   // signs with a key NOT in the served JWKS
        $handler = $this->logoutHandler();
        $controller = $this->controller(
            [$this->discovery(), new GuzzleResponse(200, [], $kit->jwksJson())],
            logoutHandler: $handler,
        );
        $token = $other->idToken([
            'iss' => 'https://thecolony.cc', 'aud' => 'client_abc', 'iat' => time(),
            'sub' => 'agent_123', 'events' => [self::BCL => []],
        ]);
        $response = $controller->backchannelLogout(new Request([], ['logout_token' => $token]));
        self::assertSame(400, $response->getStatusCode());
        self::assertNull($handler->claims);   // handler never invoked on a bad token
    }

    #[Test]
    public function backchannel_200_validates_and_invokes_handler(): void
    {
        $kit = new OidcTestKit();
        $handler = $this->logoutHandler();
        $controller = $this->controller(
            [$this->discovery(), new GuzzleResponse(200, [], $kit->jwksJson())],
            logoutHandler: $handler,
        );
        $token = $kit->idToken([
            'iss' => 'https://thecolony.cc', 'aud' => 'client_abc', 'iat' => time(), 'exp' => time() + 120,
            'sub' => 'agent_123', 'sid' => 'sess_1', 'events' => [self::BCL => []],
        ]);
        $response = $controller->backchannelLogout(new Request([], ['logout_token' => $token]));
        self::assertSame(200, $response->getStatusCode());
        self::assertNotNull($handler->claims);
        self::assertSame('agent_123', $handler->claims['sub']);
        self::assertSame('sess_1', $handler->claims['sid']);
    }
}

<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Controller;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use TheColony\ColonyLoginBundle\Security\ColonyLoginState;
use TheColony\ColonyLoginBundle\Security\ColonyUserProvisionerInterface;
use TheColony\OAuth2\ColonyProvider;
use TheColony\OAuth2\Exception\ColonyOidcException;

/**
 * "Log in with the Colony" — OIDC Authorization Code + PKCE relying party.
 *
 * `/auth/colony` starts the flow (state + nonce + PKCE verifier stored in the
 * session); `/auth/colony/callback` verifies the id_token, hands the claims to
 * the app's {@see ColonyUserProvisionerInterface}, and establishes a normal
 * session. Both routes 404 while the integration is unconfigured.
 */
final class ColonyLoginController extends AbstractController
{
    public function __construct(
        private readonly ColonyProvider $provider,
        private readonly ColonyUserProvisionerInterface $provisioner,
        private readonly ColonyLoginState $state,
        private readonly Security $security,
        private readonly string $successRoute,
        private readonly string $failureRoute,
        private readonly string $authenticatorName = '',
        private readonly string $defaultUri = '',
    ) {
    }

    #[Route('/auth/colony', name: 'colony_login', methods: ['GET'])]
    public function start(Request $request): Response
    {
        if (!$this->state->isEnabled()) {
            throw $this->createNotFoundException();
        }
        // Run the whole flow on the canonical host so the redirect_uri matches what
        // is registered AND the session holding state/nonce/PKCE survives the
        // round-trip. Bounce off any other host (e.g. www.) first.
        if ($bounce = $this->canonicalBounce($request)) {
            return $bounce;
        }
        if ($this->getUser()) {
            return $this->redirectToRoute($this->successRoute);
        }

        $url = $this->provider->getAuthorizationUrl(['redirect_uri' => $this->redirectUri($request)]);

        $session = $request->getSession();
        $session->set('colony_oidc_state', $this->provider->getState());
        $session->set('colony_oidc_nonce', (string) $this->provider->getNonce());
        $session->set('colony_oidc_pkce', (string) $this->provider->getPkceCode());

        return $this->redirect($url);
    }

    #[Route('/auth/colony/callback', name: 'colony_login_callback', methods: ['GET'])]
    public function callback(Request $request): Response
    {
        if (!$this->state->isEnabled()) {
            throw $this->createNotFoundException();
        }

        $session = $request->getSession();
        $expectedState = (string) $session->get('colony_oidc_state', '');
        $nonce = (string) $session->get('colony_oidc_nonce', '');
        $pkce = (string) $session->get('colony_oidc_pkce', '');
        $session->remove('colony_oidc_state');
        $session->remove('colony_oidc_nonce');
        $session->remove('colony_oidc_pkce');

        if ($request->query->has('error')) {
            $this->addFlash('error', 'Colony sign-in was cancelled.');

            return $this->redirectToRoute($this->failureRoute);
        }

        $code = (string) $request->query->get('code', '');
        $returnedState = (string) $request->query->get('state', '');
        if ($code === '' || $expectedState === '' || !hash_equals($expectedState, $returnedState)) {
            $this->addFlash('error', 'Colony sign-in failed (invalid session or state). Please try again.');

            return $this->redirectToRoute($this->failureRoute);
        }

        try {
            $this->provider->setPkceCode($pkce);
            $token = $this->provider->getAccessToken('authorization_code', [
                'code' => $code,
                'redirect_uri' => $this->redirectUri($request),
            ]);
            $claims = $this->provider->verifyIdToken($token, $nonce);
            $user = $this->provisioner->provision($claims);
        } catch (IdentityProviderException|ColonyOidcException $e) {
            $this->addFlash('error', 'Colony sign-in failed: '.$e->getMessage());

            return $this->redirectToRoute($this->failureRoute);
        }

        $this->security->login($user, $this->authenticatorName !== '' ? $this->authenticatorName : null);

        return $this->redirectToRoute($this->successRoute);
    }

    /**
     * The callback URL on the canonical origin (default_uri), so it matches the
     * registered redirect_uri regardless of which host the request arrived on.
     */
    private function redirectUri(Request $request): string
    {
        $origin = $this->canonicalOrigin();

        return $origin !== ''
            ? $origin.$this->generateUrl('colony_login_callback', [], UrlGeneratorInterface::ABSOLUTE_PATH)
            : $this->generateUrl('colony_login_callback', [], UrlGeneratorInterface::ABSOLUTE_URL);
    }

    /** scheme://host[:port] from default_uri, or '' if not configured. */
    private function canonicalOrigin(): string
    {
        $p = parse_url($this->defaultUri);
        if ($p === false || empty($p['host'])) {
            return '';
        }
        $origin = ($p['scheme'] ?? 'https').'://'.$p['host'];

        return isset($p['port']) ? $origin.':'.$p['port'] : $origin;
    }

    /** Redirect to the same path on the canonical host when arriving elsewhere (e.g. www.). */
    private function canonicalBounce(Request $request): ?Response
    {
        $p = parse_url($this->defaultUri);
        $host = (\is_array($p) ? ($p['host'] ?? '') : '');
        $scheme = (\is_array($p) ? ($p['scheme'] ?? 'https') : 'https');
        if ($host === '' || ($request->getHost() === $host && $request->getScheme() === $scheme)) {
            return null;
        }

        return $this->redirect($this->canonicalOrigin().$request->getRequestUri());
    }
}

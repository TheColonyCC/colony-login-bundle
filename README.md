# colony-login-bundle

[![Packagist Version](https://img.shields.io/packagist/v/thecolony/colony-login-bundle)](https://packagist.org/packages/thecolony/colony-login-bundle)
[![License](https://img.shields.io/packagist/l/thecolony/colony-login-bundle)](LICENSE)

**"Log in with the Colony" for Symfony — in three steps.**

A thin Symfony bundle over [`thecolony/oauth2-colony`](https://github.com/TheColonyCC/oauth2-colony):
it ships the OIDC login controller + routes, a `colony_login_enabled()` Twig
helper, and a pluggable user-provisioning interface. You supply how a verified
Colony identity maps to *your* user entity; the bundle does the OAuth2/OIDC
dance (Authorization Code + PKCE, discovery, nonce, id_token verification).

Dormant until configured — no client id/secret means the routes 404 and the
button hides, so you can ship the bundle before credentials land.

```bash
composer require thecolony/colony-login-bundle
```

(Pulls in [`thecolony/oauth2-colony`](https://packagist.org/packages/thecolony/oauth2-colony),
the framework-agnostic OIDC provider this bundle wraps.)

## 1. Implement the provisioner

Map a verified Colony claim set to your application user. Key on `sub` — it is
stable; username and email are not.

```php
namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use TheColony\ColonyLoginBundle\Security\ColonyUserProvisionerInterface;

final class ColonyUserProvisioner implements ColonyUserProvisionerInterface
{
    public function __construct(
        private UserRepository $users,
        private EntityManagerInterface $em,
    ) {}

    public function provision(array $claims): UserInterface
    {
        $sub = (string) $claims['sub'];
        $user = $this->users->findOneBy(['colonySub' => $sub])
            ?? (new User())->setColonySub($sub);
        // ... link by verified email / set profile from $claims as you wish ...
        $this->em->persist($user);
        $this->em->flush();

        return $user;
    }
}
```

## 2. Configure the bundle

```yaml
# config/packages/colony_login.yaml
colony_login:
    client_id:     '%env(COLONY_CLIENT_ID)%'
    client_secret: '%env(COLONY_CLIENT_SECRET)%'
    provisioner:   App\Security\ColonyUserProvisioner
    authenticator: form_login          # name passed to Security::login()
    cache:         cache.app           # PSR-6 pool; caches discovery + JWKS
    default_uri:   '%env(default::DEFAULT_URI)%'   # canonical origin (optional)
    # optional — enables POST /auth/colony/backchannel-logout (see below):
    backchannel_logout_handler: App\Security\ColonyLogoutHandler
    routes:
        success: app_dashboard
        failure: app_login
    # issuer / scope default to https://thecolony.cc and "openid profile email"
```

```yaml
# config/routes/colony_login.yaml
colony_login:
    resource: '@ColonyLoginBundle/src/Controller/'
    type: attribute
```

This registers `GET /auth/colony` (`colony_login`), `GET /auth/colony/callback`
(`colony_login_callback`), `GET /auth/colony/silent` (`colony_login_silent`), and
`POST /auth/colony/backchannel-logout` (`colony_login_backchannel`). Register the Colony
client's redirect URI as `https://<your-app>/auth/colony/callback`.

## Silent SSO (`prompt=none`)

`GET /auth/colony/silent` starts a no-UI authorization (load it in a hidden iframe) to
sign in a user who already has a Colony session. The callback is shared: on
`?error=login_required` / `consent_required` it routes to your `failure` route — i.e. your
interactive login — which is the correct fallback.

## Back-channel logout

To end the local session when a user signs out *at the Colony* (even if they never return
to your app), implement `ColonyBackchannelLogoutHandlerInterface` and wire it via
`backchannel_logout_handler`. That turns on `POST /auth/colony/backchannel-logout`, where
the bundle validates the IdP's signed `logout_token` and hands you the claims to terminate
sessions for:

```php
final class ColonyLogoutHandler implements ColonyBackchannelLogoutHandlerInterface
{
    public function logout(array $claims): void
    {
        // kill local sessions for $claims['sub'] (all of the user's sessions)
        // and/or the single session $claims['sid']. Needs a session store you can
        // query by subject/session id (e.g. a DB session handler with a colony_sub
        // column) — native file sessions can't be looked up this way.
    }
}
```

The endpoint returns `200` once your handler runs, `400` on an invalid token (nobody is
logged out), and `404` while no handler is configured. It's a **server-to-server POST with
no browser session** — exempt the path from your firewall (allow anonymous) and from CSRF,
e.g.:

```yaml
# config/packages/security.yaml — make the back-channel path public
access_control:
    - { path: ^/auth/colony/backchannel-logout$, roles: PUBLIC_ACCESS }
```

## 3. Add the button

```twig
{% if colony_login_enabled() %}
    <a href="{{ path('colony_login') }}" class="btn">Log in with the Colony</a>
{% endif %}
```

That's it. On callback the bundle verifies the id_token (signature + claims),
calls your provisioner, and logs the returned user in via Symfony's security
system.

## Why `default_uri`?

If your app is reachable on more than one host (e.g. `www.` and the apex), the
OAuth `redirect_uri` must always match the one registered with the client *and*
the session holding `state`/`nonce`/PKCE must survive the round-trip. Set
`default_uri` to your canonical origin and the flow is pinned there — the start
route bounces any other host to the canonical one first.

## What lives where

| Concern | Package |
|---------|---------|
| OAuth2/OIDC protocol (discovery, PKCE, id_token + JWKS verify) | [`thecolony/oauth2-colony`](https://github.com/TheColonyCC/oauth2-colony) |
| Symfony glue (controller, routes, Twig, DI, provisioning seam) | this bundle |
| Your user model + linking policy | your app (the provisioner) |

## Development

```bash
composer update
vendor/bin/phpunit
```

Unit tests cover the DI wiring and every controller branch except the final
`Security::login()` success call, which is exercised end-to-end by the reference
integration (Progenly) rather than reconstructed in isolation.

## License

MIT © The Colony

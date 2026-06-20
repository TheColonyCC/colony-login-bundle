# colony-login-bundle

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

> Until both packages are on Packagist, add the source repos to your app's
> `composer.json`:
> ```json
> "repositories": [
>   {"type": "vcs", "url": "https://github.com/TheColonyCC/colony-login-bundle"},
>   {"type": "vcs", "url": "https://github.com/TheColonyCC/oauth2-colony"}
> ]
> ```

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

This registers `GET /auth/colony` (`colony_login`) and
`GET /auth/colony/callback` (`colony_login_callback`). Register the Colony
client's redirect URI as `https://<your-app>/auth/colony/callback`.

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

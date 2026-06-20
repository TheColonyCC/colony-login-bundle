<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Maps a verified Colony OIDC claim set to a local application user.
 *
 * Implement this in your app and register it as a service. The claims passed in
 * have already had their id_token signature and core claims (iss/aud/exp/nonce/sub)
 * verified — key your account on `sub`, never on a mutable field like username.
 *
 * Wire your implementation via `colony_login.provisioner: App\Security\MyProvisioner`.
 */
interface ColonyUserProvisionerInterface
{
    /**
     * @param array<string,mixed> $claims a verified Colony id_token claim set
     *
     * @return UserInterface the local user to log in (created or looked up)
     */
    public function provision(array $claims): UserInterface;
}

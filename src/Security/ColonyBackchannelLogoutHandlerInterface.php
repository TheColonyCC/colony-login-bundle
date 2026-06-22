<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Security;

/**
 * Terminates local sessions when the Colony sends a back-channel `logout_token`.
 *
 * Implement this in your app and wire it via
 * `colony_login.backchannel_logout_handler: App\Security\MyLogoutHandler` to turn
 * on the `/auth/colony/backchannel-logout` endpoint. The claims passed in have
 * already been validated (signature + iss/aud/iat/events, and a `sub` and/or
 * `sid`) by {@see \TheColony\OAuth2\ColonyProvider::validateLogoutToken()}.
 *
 * Find and kill every local session for `$claims['sub']` (all of the user's
 * sessions) and/or the single session identified by `$claims['sid']`. This needs
 * a session store you can query by subject/session id (e.g. a DB-backed session
 * handler with a `colony_sub` column) — native file sessions are not enough.
 */
interface ColonyBackchannelLogoutHandlerInterface
{
    /**
     * @param array<string,mixed> $claims validated logout_token claims (`sub` and/or `sid`)
     */
    public function logout(array $claims): void;
}

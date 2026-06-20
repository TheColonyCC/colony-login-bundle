<?php

declare(strict_types=1);

namespace TheColony\ColonyLoginBundle\Tests;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/** In-process RSA signer + JWKS so controller tests verify real id_tokens offline. */
final class OidcTestKit
{
    public readonly JWK $key;

    public function __construct()
    {
        $this->key = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'test-1']);
    }

    public function jwksJson(): string
    {
        return (string) json_encode(['keys' => [$this->key->toPublic()->jsonSerialize()]]);
    }

    /** @param array<string,mixed> $claims */
    public function idToken(array $claims): string
    {
        $jws = (new JWSBuilder(new AlgorithmManager([new RS256()])))
            ->create()
            ->withPayload((string) json_encode($claims))
            ->addSignature($this->key, ['alg' => 'RS256'])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    /**
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    public static function claims(array $overrides = []): array
    {
        return array_merge([
            'iss' => 'https://thecolony.cc',
            'sub' => 'colony-sub-123',
            'aud' => 'client_abc',
            'exp' => 4102444800,
            'nonce' => 'the-nonce',
            'email' => 'agent@thecolony.cc',
            'email_verified' => true,
            'preferred_username' => 'colonist-one',
            'name' => 'Colonist One',
        ], $overrides);
    }
}

<?php

namespace SocialiteProviders\EvoPixel;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\RequestOptions;
use RuntimeException;
use Throwable;

class OpenIdConnect
{
    protected $http;
    protected $issuer;
    protected $metadata;

    public function __construct(ClientInterface $http, $issuer)
    {
        $this->http = $http;
        $this->issuer = $issuer;
    }

    /**
     * Read metadata only from the expected issuer and its fixed endpoints.
     */
    public function discovery()
    {
        if ($this->metadata !== null) {
            return $this->metadata;
        }

        $data = $this->read('/.well-known/openid-configuration');
        if (($data['issuer'] ?? null) !== $this->issuer) {
            throw new RuntimeException('OpenID Connect discovery returned a different issuer.');
        }
        foreach (['jwks_uri' => '/oauth/jwks', 'end_session_endpoint' => '/oauth/logout'] as $key => $path) {
            if (($data[$key] ?? null) !== $this->issuer.$path) {
                throw new RuntimeException('OpenID Connect discovery returned an unexpected endpoint.');
            }
        }

        return $this->metadata = $data;
    }

    /**
     * Verify the signature before accepting any identity claim.
     */
    public function validate($token, $client, $nonce = null, $accessToken = null, $maxAge = null)
    {
        try {
            if (!is_string($token) || strlen($token) > 16384 || count($parts = explode('.', $token)) !== 3) {
                throw new RuntimeException('Invalid ID token format.');
            }
            $header = (array) JWT::jsonDecode(JWT::urlsafeB64Decode($parts[0]));
            if (($header['alg'] ?? null) !== 'RS256' || ($header['typ'] ?? 'JWT') !== 'JWT'
                || !is_string($header['kid'] ?? null) || $header['kid'] === '' || isset($header['crit']) || isset($header['b64'])) {
                throw new RuntimeException('Invalid ID token header.');
            }
            $this->discovery();
            $jwks = $this->read('/oauth/jwks');
            if (!is_array($jwks['keys'] ?? null) || count($jwks['keys']) > 20) {
                throw new RuntimeException('Invalid signing keys.');
            }
            $matches = array_values(array_filter($jwks['keys'], function ($key) use ($header) {
                return is_array($key) && ($key['kid'] ?? null) === $header['kid'];
            }));
            if (count($matches) !== 1) {
                throw new RuntimeException('Unknown signing key.');
            }
            $jwk = $matches[0];
            if (($jwk['kty'] ?? null) !== 'RSA' || ($jwk['alg'] ?? 'RS256') !== 'RS256'
                || ($jwk['use'] ?? 'sig') !== 'sig' || isset($jwk['d'])
                || (isset($jwk['key_ops']) && $jwk['key_ops'] !== ['verify'])) {
                throw new RuntimeException('Invalid signing key.');
            }
            $key = JWK::parseKey($jwk, 'RS256');
            $public = $key ? openssl_pkey_get_public($key->getKeyMaterial()) : false;
            $details = $public ? openssl_pkey_get_details($public) : false;
            if (!$details || $details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < 2048) {
                throw new RuntimeException('The signing key is too weak.');
            }
            $claims = (array) JWT::decode($token, $key);
            $audiences = isset($claims['aud']) && is_array($claims['aud']) ? $claims['aud'] : [$claims['aud'] ?? null];
            if (($claims['iss'] ?? null) !== $this->issuer || !is_string($claims['sub'] ?? null)
                || !preg_match('/^[1-9][0-9]*$/D', $claims['sub']) || !in_array($client, $audiences, true)
                || count(array_filter($audiences, 'is_string')) !== count($audiences)
                || (count($audiences) > 1 && ($claims['azp'] ?? null) !== $client)
                || (isset($claims['azp']) && $claims['azp'] !== $client)
                || !is_int($claims['iat'] ?? null) || !is_int($claims['exp'] ?? null)
                || $claims['iat'] < 1 || $claims['iat'] > time() + 30 || $claims['exp'] <= time()
                || $claims['exp'] <= $claims['iat'] || isset($claims['events'])) {
                throw new RuntimeException('Invalid ID token claims.');
            }
            if ($nonce !== null && (!is_string($nonce) || $nonce === '' || !is_string($claims['nonce'] ?? null)
                || !hash_equals($nonce, $claims['nonce']))) {
                throw new RuntimeException('Invalid ID token nonce.');
            }
            if (isset($claims['auth_time']) && (!is_int($claims['auth_time']) || $claims['auth_time'] < 1 || $claims['auth_time'] > $claims['iat'] + 30)) {
                throw new RuntimeException('Invalid authentication time.');
            }
            if ($maxAge !== null && (!is_int($maxAge) || $maxAge < 0 || !isset($claims['auth_time'])
                || $claims['auth_time'] + $maxAge + 30 < time())) {
                throw new RuntimeException('A recent authentication is required.');
            }
            if (isset($claims['sid']) && (!is_string($claims['sid']) || $claims['sid'] === '' || strlen($claims['sid']) > 255)) {
                throw new RuntimeException('Invalid session identifier.');
            }
            if (isset($claims['at_hash'])) {
                $hash = is_string($accessToken) ? JWT::urlsafeB64Encode(substr(hash('sha256', $accessToken, true), 0, 16)) : '';
                if (!is_string($claims['at_hash']) || !hash_equals($hash, $claims['at_hash'])) {
                    throw new RuntimeException('The ID token does not match the access token.');
                }
            }

            return $claims;
        } catch (Throwable $exception) {
            throw new RuntimeException('EvoPixel Account returned an invalid ID token.', 0, $exception);
        }
    }

    protected function read($path)
    {
        $response = $this->http->request('GET', $this->issuer.$path, [RequestOptions::HEADERS => ['Accept' => 'application/json'],
            RequestOptions::ALLOW_REDIRECTS => false, RequestOptions::TIMEOUT => 10]);
        $body = (string) $response->getBody();
        $data = strlen($body) <= 1048576 ? json_decode($body, true) : null;
        if ($response->getStatusCode() !== 200 || !is_array($data)) {
            throw new RuntimeException('OpenID Connect returned invalid metadata.');
        }

        return $data;
    }
}

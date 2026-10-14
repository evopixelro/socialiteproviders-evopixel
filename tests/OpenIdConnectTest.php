<?php

namespace SocialiteProviders\EvoPixel\Tests;

use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SocialiteProviders\EvoPixel\OpenIdConnect;
use SocialiteProviders\EvoPixel\Provider;

class OpenIdConnectTest extends TestCase
{
    private static $privateKey;
    private static $jwk;
    private $issuer = 'https://account.evopixel.ro';

    public static function setUpBeforeClass(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, self::$privateKey);
        $details = openssl_pkey_get_details($key);
        self::$jwk = ['kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => 'key-one',
            'n' => JWT::urlsafeB64Encode($details['rsa']['n']), 'e' => JWT::urlsafeB64Encode($details['rsa']['e'])];
    }

    private function metadata()
    {
        return ['issuer' => $this->issuer, 'jwks_uri' => $this->issuer.'/oauth/jwks', 'end_session_endpoint' => $this->issuer.'/oauth/logout'];
    }

    private function claims(array $changes = [])
    {
        return array_merge(['iss' => $this->issuer, 'sub' => '123', 'aud' => 'client', 'iat' => time(), 'exp' => time() + 600,
            'auth_time' => time(), 'nonce' => 'expected-nonce', 'sid' => 'central-session',
            'at_hash' => JWT::urlsafeB64Encode(substr(hash('sha256', 'access', true), 0, 16))], $changes);
    }

    private function jwt(array $changes = [], $kid = 'key-one')
    {
        return JWT::encode($this->claims($changes), self::$privateKey, 'RS256', $kid);
    }

    private function response($data)
    {
        return new Response(200, [], json_encode($data));
    }

    private function validator(array $keys = null, array $metadata = null)
    {
        return new OpenIdConnect(new Client(['handler' => HandlerStack::create(new MockHandler([
            $this->response($metadata ?? $this->metadata()), $this->response(['keys' => $keys ?? [self::$jwk]]),
        ]))]), $this->issuer);
    }

    public function testValidSignedIdTokenAndAudienceArray()
    {
        $claims = $this->validator()->validate($this->jwt(), 'client', 'expected-nonce', 'access', 300);
        $this->assertSame('123', $claims['sub']);
        $this->assertSame('central-session', $claims['sid']);
        $this->assertSame('123', $this->validator()->validate($this->jwt(['aud' => ['client', 'other'], 'azp' => 'client']), 'client', 'expected-nonce', 'access')['sub']);
    }

    /** @dataProvider invalidClaims */
    public function testInvalidClaimsAreRejected(array $changes)
    {
        $this->expectException(RuntimeException::class);
        $this->validator()->validate($this->jwt($changes), 'client', 'expected-nonce', 'access', 300);
    }

    public function invalidClaims()
    {
        return [[['iss' => 'https://other.example']], [['aud' => 'other']], [['aud' => ['other']]],
            [['aud' => ['client', 'other']]], [['azp' => 'other']], [['sub' => '']], [['sub' => 123]], [['nonce' => 'other']],
            [['exp' => 1]], [['iat' => PHP_INT_MAX]], [['auth_time' => 1]], [['at_hash' => 'wrong']],
            [['events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass]]]];
    }

    public function testBadSignatureAndUnknownKeyAreRejected()
    {
        $parts = explode('.', $this->jwt());
        $parts[2] = str_repeat('a', strlen($parts[2]));
        try {
            $this->validator()->validate(implode('.', $parts), 'client', 'expected-nonce', 'access');
            $this->fail('A bad signature must not be accepted.');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString('invalid ID token', $exception->getMessage());
        }
        $this->expectException(RuntimeException::class);
        $this->validator()->validate($this->jwt([], 'unknown'), 'client', 'expected-nonce', 'access');
    }

    public function testKeyRotationAcceptsTheNewKid()
    {
        $new = array_replace(self::$jwk, ['kid' => 'key-two']);
        $this->assertSame('123', $this->validator([self::$jwk, $new])->validate($this->jwt([], 'key-two'), 'client', 'expected-nonce', 'access')['sub']);
    }

    public function testDuplicateKidAndWeakKeysAreRejected()
    {
        try {
            $this->validator([self::$jwk, self::$jwk])->validate($this->jwt(), 'client', 'expected-nonce', 'access');
            $this->fail('Duplicate key identifiers must not be accepted.');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString('invalid ID token', $exception->getMessage());
        }
        $weak = openssl_pkey_get_details(openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]));
        $this->expectException(RuntimeException::class);
        $this->validator([array_replace(self::$jwk, ['n' => JWT::urlsafeB64Encode($weak['rsa']['n'])])])->validate($this->jwt(), 'client', 'expected-nonce', 'access');
    }

    public function testDiscoveryCannotRedirectKeyOrLogoutRequestsElsewhere()
    {
        $this->expectException(RuntimeException::class);
        $this->validator(null, array_replace($this->metadata(), ['jwks_uri' => 'https://other.example/jwks']))->discovery();
    }

    public function testOidcCallbackValidatesNonceAndUserInfoWithDefaultCallbackScopes()
    {
        $session = new Store('oidc-test', new ArraySessionHandler(120));
        $session->start();
        $request = Request::create('/callback?code=code');
        $request->setLaravelSession($session);
        $login = new Provider($request, 'client', str_repeat('s', 32), 'https://app.example/callback');
        parse_str(parse_url($login->setScopes(['openid', 'profile', 'connections', 'offline_access'])->redirect()->getTargetUrl(), PHP_URL_QUERY), $parameters);
        $this->assertSame(64, strlen($parameters['nonce']));
        $request->query->add(['state' => $parameters['state'], 'iss' => $this->issuer]);
        $provider = new Provider($request, 'client', str_repeat('s', 32), 'https://app.example/callback');
        $history = [];
        $stack = HandlerStack::create(new MockHandler([
            $this->response(['access_token' => 'access', 'refresh_token' => 'refresh', 'scope' => 'openid profile connections offline_access',
                'expires_in' => 600, 'id_token' => $this->jwt(['nonce' => $parameters['nonce']])]),
            $this->response($this->metadata()), $this->response(['keys' => [self::$jwk]]),
            $this->response(['id' => '123', 'sub' => '123', 'name' => 'Member']),
        ]));
        $stack->push(Middleware::history($history));
        $provider->setHttpClient(new Client(['handler' => $stack]));
        $this->assertSame('123', $provider->user()->getId());
        $this->assertSame('123', $provider->getValidatedIdToken()['sub']);
        $this->assertSame($this->issuer.'/oauth/userinfo', (string) $history[3]['request']->getUri());
        $this->assertNull($session->get('code_verifier'));
        $this->assertNull($session->get('state'));
    }

    public function testOidcDowngradeWithoutIdTokenIsRejected()
    {
        $session = new Store('oidc-test', new ArraySessionHandler(120));
        $session->start();
        $request = Request::create('/callback?code=code');
        $request->setLaravelSession($session);
        $provider = new Provider($request, 'client', str_repeat('s', 32), 'https://app.example/callback');
        parse_str(parse_url($provider->scopes(['openid'])->redirect()->getTargetUrl(), PHP_URL_QUERY), $parameters);
        $request->query->add(['state' => $parameters['state'], 'iss' => $this->issuer]);
        $provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([
            $this->response(['access_token' => 'access', 'scope' => 'openid profile']),
        ]))]));
        $this->expectException(RuntimeException::class);
        $provider->user();
    }

    public function testLogoutUrlUsesDiscoveredEndpointAndPreservesApplicationState()
    {
        $request = Request::create('/');
        $provider = new Provider($request, 'client', str_repeat('s', 32), 'https://app.example/callback');
        $provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([$this->response($this->metadata())]))]));
        $url = $provider->getLogoutUrl($this->jwt(), 'https://app.example/signed-out', str_repeat('z', 32));
        $this->assertSame($this->issuer.'/oauth/logout', strtok($url, '?'));
        parse_str(parse_url($url, PHP_URL_QUERY), $query);
        $this->assertSame('client', $query['client_id']);
        $this->assertSame(str_repeat('z', 32), $query['state']);
        $this->assertSame('https://app.example/signed-out', $query['post_logout_redirect_uri']);
    }

    public function testConnectionsKeepExternalIdsAndDiscardUnexpectedSensitiveFields()
    {
        $provider = new Provider(Request::create('/'), 'client', str_repeat('s', 32), 'https://app.example/callback');
        $provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([$this->response([
            'id' => '123', 'connections' => [['provider' => 'discord', 'id' => '987654321', 'name' => 'External', 'avatar' => 'https://cdn.example/avatar.png', 'token' => 'never-return-this']],
        ])]))]));
        $this->assertSame(['id' => '123', 'connections' => [['provider' => 'discord', 'id' => '987654321', 'name' => 'External', 'avatar' => 'https://cdn.example/avatar.png']]], $provider->getConnectionsByToken('access'));
    }
}

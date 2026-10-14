<?php

namespace SocialiteProviders\EvoPixel\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Laravel\Socialite\Two\InvalidStateException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SocialiteProviders\EvoPixel\Provider;

class TokenTest extends TestCase
{
    protected $request;
    protected $session;
    protected $provider;

    protected function setUp(): void
    {
        $this->session = new Store('provider-test', new ArraySessionHandler(120));
        $this->session->start();
        $this->request = Request::create('/callback?state=expected&code=code');
        $this->request->setLaravelSession($this->session);
        $this->provider = new Provider($this->request, 'client', str_repeat('s', 64), 'https://app.example/callback');
    }

    public function testRefreshReturnsRotatedTokensAcrossSupportedSocialiteVersions()
    {
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], json_encode([
            'access_token' => 'new-access', 'refresh_token' => 'rotated-refresh', 'expires_in' => 300, 'scope' => 'profile email',
        ]))]));
        $stack->push(Middleware::history($history));
        $this->provider->setHttpClient(new Client(['handler' => $stack]));
        if (method_exists($this->provider, 'refreshToken')) {
            $tokens = $this->provider->refreshToken('old-refresh');
            $this->assertSame('new-access', $tokens->token);
            $this->assertSame('rotated-refresh', $tokens->refreshToken);
            $this->assertSame(['profile', 'email'], $tokens->approvedScopes);
        } else {
            $tokens = $this->provider->getRefreshTokenResponse('old-refresh');
            $this->assertSame('new-access', $tokens['access_token']);
            $this->assertSame('rotated-refresh', $tokens['refresh_token']);
            $this->assertSame('profile email', $tokens['scope']);
        }
        parse_str((string) $history[0]['request']->getBody(), $fields);
        $this->assertSame('refresh_token', $fields['grant_type']);
        $this->assertSame('old-refresh', $fields['refresh_token']);
        $this->assertSame('client', $fields['client_id']);
        $this->assertFalse($history[0]['options']['allow_redirects']);
        $this->assertSame(10, $history[0]['options']['timeout']);
        $this->assertStringEndsWith('/token', (string) $history[0]['request']->getUri());
    }

    public function testOfflineAccessCanBeRequestedWithOidcAndConnections()
    {
        $url = $this->provider->setScopes(['openid', 'profile', 'connections', 'offline_access'])->redirect()->getTargetUrl();
        parse_str(parse_url($url, PHP_URL_QUERY), $fields);
        $this->assertSame('openid profile connections offline_access', $fields['scope']);
        $this->assertSame('S256', $fields['code_challenge_method']);
        $this->assertNotEmpty($fields['nonce']);
        $this->assertSame($this->session->get('state'), $fields['state']);
    }

    public function testConnectionsReadUpdatedNamesAfterTokenRotationWithoutChangingTheLocalSession()
    {
        $history = [];
        $connections = function ($name) {
            return ['id' => '123', 'connections' => [['provider' => 'steam', 'id' => '76561198000000000',
                'name' => $name, 'avatar' => 'https://images.example/avatar.png']]];
        };
        $stack = HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode($connections('Original'))),
            new Response(200, [], json_encode(['access_token' => 'new-access', 'refresh_token' => 'rotated-refresh',
                'expires_in' => 600, 'scope' => 'profile connections offline_access'])),
            new Response(200, [], json_encode($connections('Updated Steam name'))),
        ]));
        $stack->push(Middleware::history($history));
        $this->provider->setHttpClient(new Client(['handler' => $stack]));
        $this->session->put('application-user', '123');
        $this->assertSame('Original', $this->provider->getConnectionsByToken('old-access')['connections'][0]['name']);
        $tokens = $this->provider->getRefreshTokenResponse('old-refresh');
        $this->assertSame('rotated-refresh', $tokens['refresh_token']);
        $this->assertSame('Updated Steam name', $this->provider->getConnectionsByToken($tokens['access_token'])['connections'][0]['name']);
        $this->assertSame('123', $this->session->get('application-user'));
        $this->assertCount(3, $history);
        $this->assertSame('Bearer old-access', $history[0]['request']->getHeaderLine('Authorization'));
        $this->assertSame('Bearer new-access', $history[2]['request']->getHeaderLine('Authorization'));
        $this->assertSame('/oauth/connections', $history[2]['request']->getUri()->getPath());
    }

    public function testRawRefreshResponseIsAvailableForOlderSocialiteVersions()
    {
        $data = ['access_token' => 'access', 'refresh_token' => 'refresh', 'expires_in' => 300, 'scope' => 'profile'];
        $this->provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(200, [], json_encode($data))]))]));
        $this->assertSame($data, $this->provider->getRefreshTokenResponse('previous'));
    }

    /** @dataProvider invalidResponses */
    public function testMalformedRefreshResponsesAreRejected($status, $body)
    {
        $this->provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([new Response($status, [], $body)]))]));
        $this->expectException(RuntimeException::class);
        $this->provider->getRefreshTokenResponse('refresh');
    }

    public function invalidResponses()
    {
        return [[302, '{"access_token":"access"}'], [200, '{}'], [200, '{"access_token":"access","refresh_token":null,"expires_in":300,"scope":"profile"}'],
            [200, '{"access_token":"access","refresh_token":"refresh","expires_in":"300","scope":"profile"}']];
    }

    public function testRevocationDoesNotEndTheApplicationSession()
    {
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200)]));
        $stack->push(Middleware::history($history));
        $this->provider->setHttpClient(new Client(['handler' => $stack]));
        $this->session->put('application-user', '123');
        $this->provider->revokeToken('refresh');
        $this->assertSame('123', $this->session->get('application-user'));
        $this->assertStringEndsWith('/revoke', (string) $history[0]['request']->getUri());
        parse_str((string) $history[0]['request']->getBody(), $fields);
        $this->assertSame(['token' => 'refresh', 'client_id' => 'client', 'client_secret' => str_repeat('s', 64)], $fields);
        $this->assertFalse($history[0]['options']['allow_redirects']);
    }

    public function testWrongIssuerIsRejectedBeforeExchangingTheCode()
    {
        $this->session->put('state', 'expected');
        $this->request->query->set('iss', 'https://other.example');
        $this->provider->setHttpClient(new Client(['handler' => function () { $this->fail('A different issuer must not receive a token request.'); }]));
        $this->expectException(InvalidStateException::class);
        $this->provider->user();
    }

    public function testStatelessLoginAndProtectedParameterOverridesAreNotAllowed()
    {
        $this->expectException(RuntimeException::class);
        $this->provider->stateless()->redirect();
    }

    public function testPkceCannotBeOverriddenThroughWithParameters()
    {
        $this->expectException(RuntimeException::class);
        $this->provider->with(['code_challenge_method' => 'plain'])->redirect();
    }

    public function testWebClientUsesSessionPkceAndSecretThroughTheTokenLifecycle()
    {
        $redirect = 'https://app.example/callback';
        parse_str(parse_url($this->provider->redirect()->getTargetUrl(), PHP_URL_QUERY), $parameters);
        $this->assertSame($redirect, $parameters['redirect_uri']);
        $this->assertSame('S256', $parameters['code_challenge_method']);
        $verifier = $this->session->get('code_verifier');
        $this->assertNotEmpty($verifier);
        $this->assertSame($this->session->get('state'), $parameters['state']);
        $this->request->query->set('state', $parameters['state']);
        $history = [];
        $stack = HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode(['access_token' => 'access', 'refresh_token' => 'refresh', 'expires_in' => 300, 'scope' => 'profile'])),
            new Response(200, [], json_encode(['id' => '123', 'name' => 'Member'])),
            new Response(200, [], json_encode(['access_token' => 'next-access', 'refresh_token' => 'next-refresh', 'expires_in' => 300, 'scope' => 'profile'])),
            new Response(200),
        ]));
        $stack->push(Middleware::history($history));
        $this->provider->setHttpClient(new Client(['handler' => $stack]));
        $this->assertSame('123', $this->provider->user()->getId());
        $this->assertSame('next-refresh', $this->provider->getRefreshTokenResponse('refresh')['refresh_token']);
        $this->provider->revokeToken('next-refresh');
        $this->assertCount(4, $history);
        foreach ([0, 2, 3] as $index) {
            parse_str((string) $history[$index]['request']->getBody(), $fields);
            $this->assertSame(str_repeat('s', 64), $fields['client_secret']);
            $this->assertSame('client', $fields['client_id']);
            $this->assertFalse($history[$index]['options']['allow_redirects']);
            if ($index === 0) $this->assertSame($verifier, $fields['code_verifier']);
        }
    }

    /** @dataProvider invalidWebCredentials */
    public function testWebClientCannotStartWithoutValidCredentials($client, $secret)
    {
        $this->provider->setConfig(new \SocialiteProviders\Manager\Config($client, $secret, 'https://app.example/callback'));
        $this->expectException(RuntimeException::class);
        $this->provider->redirect();
    }

    public function invalidWebCredentials()
    {
        return [['client', null], ['client', ''], ['client', 'short'], ['', str_repeat('s', 64)]];
    }
}

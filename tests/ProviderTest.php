<?php

namespace SocialiteProviders\EvoPixel\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Laravel\Socialite\Two\InvalidStateException;
use Mockery;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SocialiteProviders\EvoPixel\EvoPixelExtendSocialite;
use SocialiteProviders\EvoPixel\Provider;
use SocialiteProviders\Manager\SocialiteWasCalled;

class ProviderTest extends TestCase
{
    protected $request;
    protected $session;
    protected $provider;

    protected function setUp(): void
    {
        $this->session = new Store('evopixel-test', new ArraySessionHandler(120));
        $this->session->start();
        $this->request = Request::create('/callback?state=expected&code=code');
        $this->request->setLaravelSession($this->session);
        $this->provider = new Provider($this->request, 'client', str_repeat('s', 64), 'https://app.example/callback');
    }

    protected function tearDown(): void
    {
        Mockery::close();
    }

    public function testRedirectUsesTheFixedEndpointWithStateAndS256Pkce()
    {
        $url = $this->provider->redirect()->getTargetUrl();
        $this->assertSame('https://account.evopixel.ro/oauth/authorize', strtok($url, '?'));
        parse_str(parse_url($url, PHP_URL_QUERY), $fields);
        $this->assertSame('client', $fields['client_id']);
        $this->assertSame('https://app.example/callback', $fields['redirect_uri']);
        $this->assertSame('profile email', $fields['scope']);
        $this->assertSame('code', $fields['response_type']);
        $this->assertNotEmpty($fields['state']);
        $this->assertSame($this->session->get('state'), $fields['state']);
        $this->assertSame('S256', $fields['code_challenge_method']);
        $this->assertSame(rtrim(strtr(base64_encode(hash('sha256', $this->session->get('code_verifier'), true)), '+/', '-_'), '='), $fields['code_challenge']);
    }

    public function testOfflineScopePreservesOidcStateAndPkce()
    {
        $this->provider->setScopes(['openid', 'profile', 'email', 'offline_access']);
        parse_str(parse_url($this->provider->redirect()->getTargetUrl(), PHP_URL_QUERY), $fields);
        $this->assertSame('openid profile email offline_access', $fields['scope']);
        $this->assertArrayNotHasKey('access_type', $fields);
        $this->assertNotEmpty($fields['nonce']);
        $this->assertSame($this->session->get('state'), $fields['state']);
        $this->assertSame('S256', $fields['code_challenge_method']);
        $this->assertNotEmpty($fields['code_challenge']);
    }

    public function testInvalidStateDoesNotContactTheServer()
    {
        $this->session->put('state', 'different');
        $this->provider->setHttpClient(new Client(['handler' => function () {
            $this->fail('Invalid state must not send an HTTP request.');
        }]));
        $this->expectException(InvalidStateException::class);
        $this->provider->user();
    }

    public function testTokenExchangeUsesTheVerifierAndReadsTheAuthenticatedProfile()
    {
        $this->session->put(['state' => 'expected', 'code_verifier' => str_repeat('v', 64)]);
        $history = [];
        $handler = HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode(['access_token' => 'token', 'expires_in' => 600, 'scope' => 'profile email'])),
            new Response(200, [], json_encode([
                'id' => '123', 'sub' => '123', 'preferred_username' => 'Player', 'name' => 'Alex Example',
                'given_name' => 'Alex', 'family_name' => 'Example',
                'email' => 'player@example.test', 'email_verified' => false,
                'picture' => 'https://account.evopixel.ro/upload/users/avatar.png',
            ])),
        ]));
        $handler->push(Middleware::history($history));
        $this->provider->setHttpClient(new Client(['handler' => $handler]));
        $user = $this->provider->user();
        $this->assertSame('123', $user->getId());
        $this->assertSame('Player', $user->getNickname());
        $this->assertSame('Alex Example', $user->getName());
        $this->assertSame('Alex', $user->given_name);
        $this->assertSame('Example', $user->family_name);
        $this->assertSame('Alex', $user->getRaw()['given_name']);
        $this->assertSame('Example', $user->getRaw()['family_name']);
        $this->assertSame('player@example.test', $user->getEmail());
        $this->assertSame('token', $user->token);
        $this->assertSame(600, $user->expiresIn);
        $this->assertSame('profile email', $user->accessTokenResponseBody['scope']);
        $this->assertFalse($user->getRaw()['email_verified']);
        $this->assertSame('https://account.evopixel.ro/upload/users/avatar.png', $user->getAvatar());
        $this->assertSame('https://account.evopixel.ro/oauth/token', (string) $history[0]['request']->getUri());
        $this->assertSame('https://account.evopixel.ro/oauth/user', (string) $history[1]['request']->getUri());
        parse_str((string) $history[0]['request']->getBody(), $fields);
        $this->assertSame('code', $fields['code']);
        $this->assertSame('client', $fields['client_id']);
        $this->assertSame(str_repeat('s', 64), $fields['client_secret']);
        $this->assertSame(str_repeat('v', 64), $fields['code_verifier']);
        $this->assertSame('authorization_code', $fields['grant_type']);
        $this->assertSame('Bearer token', $history[1]['request']->getHeaderLine('Authorization'));
        $this->assertFalse($history[0]['options']['allow_redirects']);
        $this->assertFalse($history[1]['options']['allow_redirects']);
        $this->assertNull($this->session->get('code_verifier'));
        $this->assertNull($this->session->get('state'));
    }

    public function testMissingEmailAndInvalidOptionalFieldsDoNotBecomeTrustedProfileData()
    {
        $this->profileResponse(['id' => '123', 'preferred_username' => [], 'name' => [], 'email' => [], 'picture' => 'http://untrusted.example/avatar.png']);
        $user = $this->provider->userFromToken('token');
        $this->assertSame('123', $user->getName());
        $this->assertSame('123', $user->getNickname());
        $this->assertNull($user->getEmail());
        $this->assertNull($user->getAvatar());
    }

    /**
     * @dataProvider invalidProfiles
     */
    public function testInvalidProfilesAreRejected($body)
    {
        $this->provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(200, [], $body)]))]));
        $this->expectException(RuntimeException::class);
        $this->provider->userFromToken('token');
    }

    public function invalidProfiles()
    {
        return [['not-json'], ['null'], ['{}'], ['{"id":123}'], ['{"id":"<script>"}'], ['{"id":"player"}'], ['{"id":"0"}'], ['{"id":"-1"}']];
    }

    public function testInvalidTokenResponseDoesNotRequestAProfile()
    {
        $this->session->put(['state' => 'expected', 'code_verifier' => str_repeat('v', 64)]);
        $this->provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(200, [], '{}')]))]));
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('invalid access token');
        $this->provider->user();
    }

    public function testRejectedTokensDoNotAuthenticate()
    {
        $this->provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(401)]))]));
        $this->expectException(ClientException::class);
        $this->provider->userFromToken('invalid');
    }

    public function testMissingCredentialsCannotStartAuthorization()
    {
        $provider = new Provider($this->request, 'client', '', 'https://app.example/callback');
        $this->expectException(RuntimeException::class);
        $provider->redirect();
    }

    public function testListenerRegistersTheEvoPixelDriver()
    {
        $event = Mockery::mock(SocialiteWasCalled::class);
        $event->shouldReceive('extendSocialite')->once()->with('evopixel', Provider::class);
        (new EvoPixelExtendSocialite())->handle($event);
        $this->addToAssertionCount(1);
    }

    public function testProfileScopeDoesNotRequireAnEmail()
    {
        $this->provider->setScopes(['profile']);
        parse_str(parse_url($this->provider->redirect()->getTargetUrl(), PHP_URL_QUERY), $fields);
        $this->assertSame('profile', $fields['scope']);
        $this->profileResponse(['id' => '123', 'preferred_username' => 'alex', 'name' => ' ',
            'picture' => 'https://lh3.googleusercontent.com/a/avatar']);
        $user = $this->provider->userFromToken('token');
        $this->assertSame('alex', $user->getName());
        $this->assertNull($user->getEmail());
        $this->assertSame('https://lh3.googleusercontent.com/a/avatar', $user->getAvatar());
    }

    public function testEmailOnlyProfilePreservesTheStableIdentity()
    {
        $this->profileResponse(['id' => '123', 'sub' => '123', 'email' => 'alex@example.test', 'email_verified' => true]);
        $user = $this->provider->userFromToken('token');
        $this->assertSame('123', $user->getId());
        $this->assertSame('123', $user->getNickname());
        $this->assertSame('123', $user->getName());
        $this->assertSame('alex@example.test', $user->getEmail());
        $this->assertTrue($user->getRaw()['email_verified']);
        $this->assertNull($user->given_name);
        $this->assertNull($user->family_name);
        $this->assertArrayNotHasKey('given_name', $user->getRaw());
        $this->assertArrayNotHasKey('family_name', $user->getRaw());
        $this->assertNull($user->getAvatar());
    }

    public function testProfileNamePartsAreAvailableWithoutSplittingTheFullName()
    {
        $profile = ['id' => '123', 'sub' => '123', 'name' => 'Community Member',
            'given_name' => 'Ana-Maria', 'family_name' => 'de la Cruz'];
        $this->profileResponse($profile);
        $user = $this->provider->userFromToken('token');
        $this->assertSame('Community Member', $user->getName());
        $this->assertSame('Ana-Maria', $user->given_name);
        $this->assertSame('de la Cruz', $user->family_name);
        $this->assertSame($profile, $user->getRaw());
    }

    /**
     * @dataProvider optionalNameParts
     */
    public function testMissingOrInvalidNamePartsRemainOptional(array $profile, $givenName, $familyName)
    {
        $this->profileResponse(['id' => '123', 'name' => 'Community Member'] + $profile);
        $user = $this->provider->userFromToken('token');
        $this->assertSame('Community Member', $user->getName());
        $this->assertSame($givenName, $user->given_name);
        $this->assertSame($familyName, $user->family_name);
        $this->assertSame(['id' => '123', 'name' => 'Community Member'] + $profile, $user->getRaw());
    }

    public function optionalNameParts()
    {
        return [
            [[], null, null],
            [['given_name' => null, 'family_name' => null], null, null],
            [['given_name' => [], 'family_name' => 123], null, null],
            [['given_name' => '', 'family_name' => ''], '', ''],
        ];
    }

    public function testProfileRedirectIsNotFollowed()
    {
        $history = [];
        $handler = HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://other.example/profile']),
        ]));
        $handler->push(Middleware::history($history));
        $this->provider->setHttpClient(new Client(['handler' => $handler]));
        try {
            $this->provider->userFromToken('token');
            $this->fail('A redirect must not authenticate a user.');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString('invalid profile', $exception->getMessage());
        }
        $this->assertCount(1, $history);
    }


    public function testOptionalAccessFieldsAreMappedAndRawProfileIsPreserved()
    {
        $profile = ['id' => '123', 'sub' => '123', 'locale' => 'ro', 'status' => 'Active',
            'role' => ['id' => '2', 'name' => 'Reader', 'display_name' => 'Readers'], 'permissions' => ['books.admin', 'users.manage']];
        $this->profileResponse($profile);
        $user = $this->provider->userFromToken('token');
        $this->assertSame('ro', $user->locale);
        $this->assertSame('Active', $user->status);
        $this->assertSame($profile['role'], $user->role);
        $this->assertSame(['books.admin', 'users.manage'], $user->permissions);
        $this->assertSame($profile, $user->getRaw());
    }

    public function testUnrequestedFieldsAreNullAndEmptyPermissionsRemainAnEmptyArray()
    {
        $this->profileResponse(['id' => '123']);
        $user = $this->provider->userFromToken('token');
        foreach (['locale', 'status', 'role', 'permissions'] as $field) $this->assertNull($user->$field);
        $this->profileResponse(['id' => '123', 'role' => null, 'permissions' => []]);
        $user = $this->provider->userFromToken('other-token');
        $this->assertSame([], $user->permissions);
    }

    public function testFreshAccessReflectsRevokedPermissionsAndUsesBearerWithoutRedirects()
    {
        $history = [];
        $handler = HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode(['id' => '123', 'sub' => '123', 'permissions' => ['books.admin', 'users.manage']])),
            new Response(200, [], json_encode(['id' => '123', 'sub' => '123', 'permissions' => []])),
        ]));
        $handler->push(Middleware::history($history));
        $this->provider->setHttpClient(new Client(['handler' => $handler]));
        $this->assertSame(['books.admin', 'users.manage'], $this->provider->getAccessByToken('token')['permissions']);
        $this->assertSame([], $this->provider->getAccessByToken('token')['permissions']);
        $this->assertCount(2, $history);
        foreach ($history as $call) {
            $this->assertSame('https://account.evopixel.ro/oauth/access', (string) $call['request']->getUri());
            $this->assertSame('Bearer token', $call['request']->getHeaderLine('Authorization'));
            $this->assertFalse($call['options']['allow_redirects']);
            $this->assertSame(10, $call['options']['timeout']);
        }
    }

    /** @dataProvider accessFailures */
    public function testAccessFailuresDoNotReusePreviousPermissions($status)
    {
        $handler = HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode(['id' => '123', 'sub' => '123', 'permissions' => ['books.admin', 'users.manage']])),
            new Response($status, [], json_encode(['error' => 'denied'])),
        ]));
        $this->provider->setHttpClient(new Client(['handler' => $handler]));
        $this->assertSame(['books.admin', 'users.manage'], $this->provider->getAccessByToken('token')['permissions']);
        $this->expectException(ClientException::class);
        $this->provider->getAccessByToken('token');
    }

    public function accessFailures()
    {
        return [[401], [403]];
    }

    /** @dataProvider malformedAccess */
    public function testInvalidAccessDataIsRejected(array $fields)
    {
        $this->profileResponse($fields + ['id' => '123', 'sub' => '123']);
        $this->expectException(RuntimeException::class);
        $this->provider->getAccessByToken('token');
    }

    public function malformedAccess()
    {
        return [[[]], [['id' => '0', 'permissions' => []]], [['sub' => '456', 'permissions' => []]],
            [['permissions' => null]], [['permissions' => 'books.admin']], [['permissions' => [true]]],
            [['permissions' => ['admin' => true]]], [['role' => 'Admin']],
            [['role' => ['id' => 1, 'name' => 'Admin']]]];
    }

    public function testRoleAndPermissionScopesAreExplicitlyRequested()
    {
        $this->provider->setScopes(['profile', 'roles', 'permissions']);
        parse_str(parse_url($this->provider->redirect()->getTargetUrl(), PHP_URL_QUERY), $fields);
        $this->assertSame('profile roles permissions', $fields['scope']);
    }

    protected function profileResponse(array $profile)
    {
        $this->provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode($profile)),
        ]))]));
    }
}

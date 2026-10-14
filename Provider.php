<?php

namespace SocialiteProviders\EvoPixel;

use GuzzleHttp\RequestOptions;
use RuntimeException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'EVOPIXEL';

    /**
     * Base URL for EvoPixel Account.
     */
    protected const BASE_URL = 'https://account.evopixel.ro';

    /**
     * {@inheritdoc}
     */
    protected $scopes = [
        'profile',
        'email',
    ];

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * {@inheritdoc}
     */
    protected $usesPKCE = true;

    /**
     * Validated claims and the access token they belong to.
     */
    protected $validatedIdToken;
    protected $validatedAccessToken;

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        if ($this->isStateless() || !$this->clientId || strlen((string) $this->clientSecret) < 32) {
            throw new RuntimeException('EvoPixel Account OAuth credentials are not configured.');
        }

        return $this->buildAuthUrlFromBase(
            static::BASE_URL.'/oauth/authorize',
            $state
        );
    }

    /**
     * Bind optional OIDC authentication to the existing state and PKCE session.
     */
    protected function getCodeFields($state = null)
    {
        foreach (['state', 'nonce', 'client_id', 'redirect_uri', 'scope', 'response_type', 'code_challenge', 'code_challenge_method'] as $field) {
            if (array_key_exists($field, $this->parameters)) {
                throw new RuntimeException('Use the provider configuration for protected OAuth parameters.');
            }
        }
        $fields = parent::getCodeFields($state);
        $this->request->session()->forget($this->oidcSessionKey());
        if (in_array('openid', $this->getScopes(), true)) {
            $maxAge = $fields['max_age'] ?? null;
            if ($maxAge !== null && filter_var($maxAge, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => 31536000]]) === false) {
                throw new RuntimeException('Invalid OpenID Connect max_age.');
            }
            $fields['nonce'] = bin2hex(random_bytes(32));
            $this->request->session()->put($this->oidcSessionKey(), ['nonce' => $fields['nonce'],
                'max_age' => $maxAge === null ? null : (int) $maxAge, 'expires' => time() + 600,
                'client_id' => $this->clientId, 'redirect_uri' => $this->redirectUrl]);
        }

        return $fields;
    }

    /**
     * Reject another issuer before sending the authorization code.
     */
    protected function hasInvalidState()
    {
        if (parent::hasInvalidState()) {
            return true;
        }
        $issuer = $this->request->input('iss');

        return ($issuer !== null && $issuer !== static::BASE_URL)
            || ($this->request->session()->has($this->oidcSessionKey()) && $issuer !== static::BASE_URL);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return static::BASE_URL.'/oauth/token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        if ($this->validatedIdToken && $this->validatedAccessToken === hash('sha256', $token)) {
            $user = $this->readResponse('/oauth/userinfo', $token);
            if (($user['sub'] ?? null) !== $this->validatedIdToken['sub'] || ($user['id'] ?? null) !== $this->validatedIdToken['sub']) {
                throw new RuntimeException('The UserInfo response does not match the ID token.');
            }

            return $user;
        }

        return $this->readResponse('/oauth/user', $token);
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenResponse($code)
    {
        $context = $this->request->session()->pull($this->oidcSessionKey());
        $this->validatedIdToken = $this->validatedAccessToken = null;
        $data = $this->tokenRequest($this->getTokenFields($code));
        if ($context || isset($data['id_token']) || in_array('openid', $this->getScopes(), true)) {
            if (!is_array($context) || ($context['expires'] ?? 0) <= time()
                || ($context['client_id'] ?? null) !== $this->clientId || ($context['redirect_uri'] ?? null) !== $this->redirectUrl
                || !in_array('openid', explode(' ', $data['scope'] ?? ''), true)) {
                throw new RuntimeException('The OpenID Connect authentication session is missing or expired.');
            }
            $this->validatedIdToken = $this->openIdConnect()->validate($data['id_token'] ?? null, $this->clientId,
                $context['nonce'], $data['access_token'], $context['max_age']);
            $this->validatedAccessToken = hash('sha256', $data['access_token']);
        }

        return $data;
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        $this->validateIdentity($user);
        $this->validateAccess($user);

        $avatar = $user['picture'] ?? null;

        if (!is_string($avatar) || !filter_var($avatar, FILTER_VALIDATE_URL) || parse_url($avatar, PHP_URL_SCHEME) !== 'https') {
            $avatar = null;
        }

        $nickname = is_string($user['preferred_username'] ?? null) && trim($user['preferred_username']) !== ''
            ? $user['preferred_username'] : $user['id'];
        $name = is_string($user['name'] ?? null) && trim($user['name']) !== '' ? $user['name'] : $nickname;

        return (new User())->setRaw($user)->map([
            'id'          => $user['id'],
            'nickname'    => $nickname,
            'name'        => $name,
            'given_name'  => is_string($user['given_name'] ?? null) ? $user['given_name'] : null,
            'family_name' => is_string($user['family_name'] ?? null) ? $user['family_name'] : null,
            'email'       => is_string($user['email'] ?? null) ? (filter_var($user['email'], FILTER_VALIDATE_EMAIL) ?: null) : null,
            'avatar'      => $avatar,
            'locale'      => is_string($user['locale'] ?? null) ? $user['locale'] : null,
            'status'      => is_string($user['status'] ?? null) ? $user['status'] : null,
            'role'        => $user['role'] ?? null,
            'permissions' => $user['permissions'] ?? null,
        ]);
    }

    /**
     * Read current access without reusing a cached Socialite user.
     */
    public function getAccessByToken($token)
    {
        $access = $this->readResponse('/oauth/access', $token);
        $this->validateIdentity($access);

        if (($access['sub'] ?? null) !== $access['id']
            || (!array_key_exists('role', $access) && !array_key_exists('permissions', $access))) {
            throw new RuntimeException('EvoPixel Account returned invalid access data.');
        }

        $this->validateAccess($access);

        return $access;
    }

    /**
     * Read an authenticated Account response.
     */
    protected function readResponse($path, $token)
    {
        $response = $this->getHttpClient()->get(
            static::BASE_URL.$path,
            [
                RequestOptions::HEADERS => [
                    'Authorization' => 'Bearer '.$token,
                    'Accept' => 'application/json',
                ],
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::TIMEOUT => 10,
            ]
        );

        $user = json_decode((string) $response->getBody(), true);

        if ($response->getStatusCode() !== 200 || !is_array($user)) {
            throw new RuntimeException('EvoPixel Account returned an invalid profile.');
        }

        return $user;
    }

    /**
     * Validate the numeric Account user ID.
     */
    protected function validateIdentity(array $user)
    {
        if (!is_string($user['id'] ?? null) || !preg_match('/^[1-9][0-9]*$/D', $user['id'])) {
            throw new RuntimeException('EvoPixel Account returned an invalid identity.');
        }
    }

    /**
     * Validate optional role and permission claims.
     */
    protected function validateAccess(array $user)
    {
        if (isset($user['role'])) {
            $role = $user['role'];

            if (!is_array($role) || !is_string($role['id'] ?? null) || !preg_match('/^[1-9][0-9]*$/D', $role['id'])
                || !is_string($role['name'] ?? null) || $role['name'] === ''
                || (isset($role['display_name']) && !is_string($role['display_name']))) {
                throw new RuntimeException('EvoPixel Account returned an invalid role.');
            }
        }

        if (array_key_exists('permissions', $user)) {
            $permissions = $user['permissions'];

            if (!is_array($permissions) || array_values($permissions) !== $permissions
                || count(array_filter($permissions, function ($permission) {
                    return is_string($permission) && $permission !== '';
                })) !== count($permissions)) {
                throw new RuntimeException('EvoPixel Account returned invalid permissions.');
            }
        }
    }

    /**
     * Read a rotated token response without following redirects or retrying it.
     */
    public function getRefreshTokenResponse($refreshToken)
    {
        if (!is_string($refreshToken) || $refreshToken === '' || strlen($refreshToken) > 512) {
            throw new RuntimeException('A refresh token is required.');
        }

        $fields = ['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken, 'client_id' => $this->clientId];
        if ($this->clientSecret !== null && $this->clientSecret !== '') {
            $fields['client_secret'] = $this->clientSecret;
        }

        $data = $this->tokenRequest($fields);
        if (!is_string($data['refresh_token'] ?? null) || $data['refresh_token'] === ''
            || !is_int($data['expires_in'] ?? null) || $data['expires_in'] < 1 || !is_string($data['scope'] ?? null)) {
            throw new RuntimeException('The server returned an invalid refresh token response.');
        }

        if (isset($data['id_token'])) {
            $claims = $this->openIdConnect()->validate($data['id_token'], $this->clientId, null, $data['access_token']);
            if ($this->validatedIdToken && ($claims['sub'] !== $this->validatedIdToken['sub']
                || ($claims['auth_time'] ?? null) !== ($this->validatedIdToken['auth_time'] ?? null)
                || (isset($claims['nonce']) && $claims['nonce'] !== ($this->validatedIdToken['nonce'] ?? null)))) {
                throw new RuntimeException('The refreshed ID token changed the authenticated identity.');
            }
            $this->validatedIdToken = $claims;
            $this->validatedAccessToken = hash('sha256', $data['access_token']);
        }

        return $data;
    }

    /**
     * Revoke this client's token without closing the application's session.
     */
    public function revokeToken($token)
    {
        if (!is_string($token) || $token === '' || strlen($token) > 512) {
            throw new RuntimeException('A token is required.');
        }
        $fields = ['token' => $token, 'client_id' => $this->clientId];
        if ($this->clientSecret !== null && $this->clientSecret !== '') {
            $fields['client_secret'] = $this->clientSecret;
        }
        $response = $this->getHttpClient()->post(str_replace('/token', '/revoke', $this->getTokenUrl()), [
            RequestOptions::HEADERS => ['Accept' => 'application/json'], RequestOptions::FORM_PARAMS => $fields,
            RequestOptions::ALLOW_REDIRECTS => false, RequestOptions::TIMEOUT => 10,
        ]);
        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException('Token revocation failed.');
        }
    }

    /**
     * Use one bounded HTTP exchange for authorization codes and refresh tokens.
     */
    protected function tokenRequest(array $fields)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS => ['Accept' => 'application/json'], RequestOptions::FORM_PARAMS => $fields,
            RequestOptions::ALLOW_REDIRECTS => false, RequestOptions::TIMEOUT => 10,
        ]);
        $body = (string) $response->getBody();
        $data = strlen($body) <= 1048576 ? json_decode($body, true) : null;
        if ($response->getStatusCode() !== 200 || !is_array($data)
            || !is_string($data['access_token'] ?? null) || $data['access_token'] === ''
            || preg_match('/[\x00-\x20\x7f]/', $data['access_token'])) {
            throw new RuntimeException('The server returned an invalid access token.');
        }

        return $data;
    }

    /**
     * Namespace the OIDC session context for this client.
     */
    protected function oidcSessionKey()
    {
        return 'socialite.evopixel.oidc.'.hash('sha256', (string) $this->clientId);
    }

    /**
     * Create the OIDC verifier for the configured issuer.
     */
    protected function openIdConnect()
    {
        return new OpenIdConnect($this->getHttpClient(), static::BASE_URL);
    }

    /**
     * Return claims only after signature and claim validation has succeeded.
     */
    public function getValidatedIdToken()
    {
        return $this->validatedIdToken;
    }

    /**
     * Return the verified issuer metadata.
     */
    public function getOpenIdConfiguration()
    {
        return $this->openIdConnect()->discovery();
    }

    /**
     * Build an RP logout request; the caller manages its own session and state.
     */
    public function getLogoutUrl($idTokenHint, $postLogoutRedirectUri, $state)
    {
        $parts = is_string($postLogoutRedirectUri) ? parse_url($postLogoutRedirectUri) : false;
        if (!is_string($idTokenHint) || strlen($idTokenHint) > 16384 || count(explode('.', $idTokenHint)) !== 3
            || !is_string($state) || strlen($state) < 16 || strlen($state) > 512
            || !$parts || ($parts['scheme'] ?? '') !== 'https' || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || !filter_var($postLogoutRedirectUri, FILTER_VALIDATE_URL) || preg_match('/[\x00-\x20\x7f]/', $postLogoutRedirectUri)) {
            throw new RuntimeException('Invalid OpenID Connect logout parameters.');
        }

        return $this->getOpenIdConfiguration()['end_session_endpoint'].'?'.http_build_query([
            'id_token_hint' => $idTokenHint, 'client_id' => $this->clientId,
            'post_logout_redirect_uri' => $postLogoutRedirectUri, 'state' => $state,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Read only the external accounts linked to this access token's owner.
     */
    public function getConnectionsByToken($token)
    {
        $data = $this->readResponse('/oauth/connections', $token);
        $this->validateIdentity($data);
        if (!is_array($data['connections'] ?? null) || array_values($data['connections']) !== $data['connections']) {
            throw new RuntimeException('EvoPixel Account returned invalid connections.');
        }
        $connections = [];
        foreach ($data['connections'] as $connection) {
            if (!is_array($connection) || !is_string($connection['provider'] ?? null)
                || !preg_match('/^[a-z][a-z0-9_]{0,63}$/D', $connection['provider'])
                || !is_string($connection['id'] ?? null) || $connection['id'] === '' || strlen($connection['id']) > 255
                || !is_string($connection['name'] ?? null) || isset($connections[$connection['provider']])) {
                throw new RuntimeException('EvoPixel Account returned an invalid linked account.');
            }
            $connections[$connection['provider']] = ['provider' => $connection['provider'], 'id' => $connection['id'],
                'name' => $connection['name'], 'avatar' => $this->connectionAvatar($connection['avatar'] ?? null)];
        }

        return ['id' => $data['id'], 'connections' => array_values($connections)];
    }

    /**
     * Validate an external account avatar URL or inline image.
     */
    protected function connectionAvatar($avatar)
    {
        if (!is_string($avatar) || strlen($avatar) > 2097152) {
            return null;
        }
        if (preg_match('#^data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)$#D', $avatar, $matches)) {
            $bytes = base64_decode($matches[2], true);
            $image = $bytes === false ? false : @getimagesizefromstring($bytes);

            return $image && $image['mime'] === 'image/'.$matches[1] && $image[0] <= 2048 && $image[1] <= 2048 ? $avatar : null;
        }
        $parts = parse_url($avatar);

        return strlen($avatar) <= 2048 && filter_var($avatar, FILTER_VALIDATE_URL) && ($parts['scheme'] ?? '') === 'https'
            && !isset($parts['user']) && !isset($parts['pass']) ? $avatar : null;
    }
}

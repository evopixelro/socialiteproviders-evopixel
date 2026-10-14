# Socialite Providers EvoPixel

EvoPixel Account OAuth2 provider for Laravel Socialite

```bash
composer require evopixel/socialiteproviders-evopixel
```

## Installation & Basic Usage

Please see the [Base Installation Guide](https://socialiteproviders.com/usage/), then follow the provider specific instructions below.

Requires PHP 7.4 or 8.x, SocialiteProviders Manager 4.x from 4.3, and Laravel Socialite 5.2.1 or later for PKCE. Composer installs compatible dependencies.

### Add configuration to `config/services.php`

```php
'evopixel' => [
    'client_id' => env('EVOPIXEL_CLIENT_ID'),
    'client_secret' => env('EVOPIXEL_CLIENT_SECRET'),
    'redirect' => env('EVOPIXEL_REDIRECT_URI'),
],
```

Create a **Web** application in [EvoPixel Account](https://account.evopixel.ro/applications), enable `profile` and `email`, and use its client ID, secret and registered callback URL. Keep the secret on the server and make sure the HTTPS callback URL matches exactly.

### Add provider event listener

Configure the package's listener to listen for `SocialiteWasCalled` events.

#### Laravel 11+

Register the listener in the `boot()` method of `App\Providers\AppServiceProvider`:

```php
\Illuminate\Support\Facades\Event::listen(function (\SocialiteProviders\Manager\SocialiteWasCalled $event) {
    $event->extendSocialite('evopixel', \SocialiteProviders\EvoPixel\Provider::class);
});
```

#### Laravel 10 or below

Add the event to your `listen[]` array in `app/Providers/EventServiceProvider`. See the [Base Installation Guide](https://socialiteproviders.com/usage/) for detailed instructions.

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        // ... other providers
        \SocialiteProviders\EvoPixel\EvoPixelExtendSocialite::class.'@handle',
    ],
];
```

### Usage

You should now be able to use the provider like you would regularly use Socialite (assuming you have the facade installed):

```php
return Socialite::driver('evopixel')->redirect();
```

Retrieve the authenticated user in your callback:

```php
$user = Socialite::driver('evopixel')->user();
```

Both routes must use session middleware. Keep the session between redirect and callback for state and S256 PKCE validation; do not use `stateless()` for this flow. Handle rejected authorization and failed requests through your application's authentication error flow.

The default scopes are `profile` and `email`. Use `setScopes(['profile'])` before `redirect()` if email is not needed.

This package uses a Web OAuth client, with credentials and the callback handled by Laravel. A SPA frontend can use this flow through its Laravel backend; keep the client secret and OAuth tokens on the server.

### Returned User fields

- `id`
- `nickname`
- `name`
- `email`
- `avatar`
- `given_name`
- `family_name`
- `locale`
- `status`
- `role`
- `permissions`

Additional response data:

- `sub`, `preferred_username`, `picture` and `email_verified` are available through `$user->getRaw()` when included in the granted profile.
- `connections` is returned separately by `getConnectionsByToken($user->token)` with the `connections` scope. Each entry contains `provider`, `id`, `name` and `avatar`; see [Linked accounts](#linked-accounts).

`id` is the Account user ID as a string. `nickname` maps `preferred_username`; `avatar` maps `picture`. `name` contains the display name, falling back to the nickname or ID. First and last names are available separately as `$user->given_name` and `$user->family_name`.

Profile fields require `profile`; email requires `email`. `locale` is the selected language or `null` for Automatic. Optional fields omitted by Account map to `null`. The complete response is available through `$user->getRaw()`, including `sub` (the same user ID) and `email_verified`. Use the provider and `id` to identify linked accounts.

`role` requires `roles` and contains `id`, `name` and `display_name`, or `null`. `permissions` requires `permissions` and contains exact permission names, or an empty array when none are assigned. Check permission names rather than role IDs or display names.

### Roles and permissions

Request `roles` or `permissions` through the provider when these scopes are enabled for your application:

```php
return Socialite::driver('evopixel')
    ->setScopes(['profile', 'email', 'roles', 'permissions'])
    ->redirect();
```

The `permissions` scope returns all current permission names assigned through the user's Account role. It does not grant permissions. For later access checks, fetch current access with the server-side token instead of relying on the login profile:

```php
$access = Socialite::driver('evopixel')->getAccessByToken($accessToken);

abort_unless(
    $access['id'] === (string) $linkedAccountId
        && in_array('books.admin', $access['permissions'] ?? [], true),
    403
);
```

`getAccessByToken()` calls `/oauth/access` on every invocation and returns `id`, `sub` and the granted `role` and/or `permissions` fields. Deny the action if the request fails. Access tokens expire after 10 minutes. A 401 response requires refresh or authorization again; 403 indicates that the required scope was not granted.

### Linked accounts

Include `connections` in `setScopes()` when this scope is enabled for your application, then read current connections separately:

```php
$data = Socialite::driver('evopixel')->getConnectionsByToken($accessToken);
```

The response contains the Account `id` and a `connections` list. Each entry contains only `provider`, the external account's `id`, `name` and `avatar`. Unlinked or unavailable providers do not appear. Check the returned Account ID against the signed-in user before using the result. Microsoft avatars may be validated inline images.

Each `getConnectionsByToken()` call retrieves the latest saved data. The request schedules a background update when an eligible linked profile has not been synchronized for at least 24 hours. A response may still contain the previous name or avatar while an update is pending; read the connections again when your application needs current data.

### Refresh tokens and revocation

Request a refresh token with the `offline_access` scope. The resulting Socialite user exposes `refreshToken` when refresh access is granted.

```php
return Socialite::driver('evopixel')
    ->setScopes(['openid', 'profile', 'email', 'offline_access'])
    ->redirect();
```

Refresh tokens renew API access. Your application manages its own session.

```php
$tokens = Socialite::driver('evopixel')->getRefreshTokenResponse($storedRefreshToken);
// Replace both stored tokens atomically; each refresh token can be used once.
$accessToken = $tokens['access_token'];
$refreshToken = $tokens['refresh_token'];
```

Serialize refresh requests for the same authorization. Do not retry a consumed token: reuse revokes its token family. If the request fails or its outcome is unknown, authorize again. Store tokens encrypted on the server and never place them in URLs or logs.

`getRefreshTokenResponse()` returns the complete response array on all supported versions. If your Laravel Socialite version provides `refreshToken()`, you can also use that method to receive a token object. Both methods retain the granted scopes.

`revokeToken($token)` accepts an access or refresh token. Revocation does not close your Laravel session; handle local logout in your application.

### Optional OpenID Connect

To request a signed ID token, add `openid` to the login scopes:

```php
return Socialite::driver('evopixel')
    ->setScopes(['openid', 'profile', 'email'])
    ->redirect();
```

Use the same `user()` callback. The provider creates and checks a session-bound nonce, validates the RS256 signature through discovery and JWKS, checks issuer, audience, expiry and applicable claims, and matches UserInfo to the ID token's subject. It rejects OIDC callbacks without the expected issuer or ID token. `with(['max_age' => 300])` can require a recent authentication.

```php
$provider = Socialite::driver('evopixel');
$user = $provider->user();
$claims = $provider->getValidatedIdToken();
$idToken = $user->accessTokenResponseBody['id_token'];
```

`getValidatedIdToken()` returns validated claims after OIDC login or a refresh response containing an ID token. When refreshing an existing login, keep its issuer and subject association; never replace a user's identity solely because a different token response was received. Calling `userFromToken()` remains an OAuth profile lookup.

### OpenID Connect logout

Central logout is available only to official EvoPixel platform applications. Personal applications should end their local session and revoke their tokens. For an eligible application with a registered post-logout URL, store a random logout state in your session, then use:

```php
$url = Socialite::driver('evopixel')->getLogoutUrl(
    $storedIdToken,
    'https://your-app.example/signed-out',
    $logoutState
);
return redirect()->away($url);
```

The provider discovers `end_session_endpoint` through `getOpenIdConfiguration()`. Account validates the signed hint, current session and registered redirect before logging out. Verify and consume your logout state when the user returns. Clear your application's session separately. Local logout need not end the Account session. Receiving Back-Channel Logout and invalidating local sessions are responsibilities of the application using this library.

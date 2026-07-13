# REST API OIDC Authentication

This guide explains how to authenticate **REST API** requests using a JWT access token issued by an external OpenID Connect (OIDC) provider, such as [Microsoft Entra ID](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id). This is distinct from [SSO](./overview.md), which authenticates interactive **web UI** logins; this feature authenticates programmatic API clients (for example, an MCP middleware using the OAuth 2.0 On-Behalf-Of flow) without issuing a native NetBox token.

!!! note
    When enabled, a client may present an access token as `Authorization: Bearer <access_token>`. NetBox validates the token against the provider's signing keys and maps it to a NetBox user. That user's [object permissions](../permissions.md) then govern API access exactly as they do for a session- or token-authenticated request — NetBox performs no additional authorization based on the token itself.

## How it works

1. The client obtains an access token from the OIDC provider whose audience (`aud`) is the NetBox application (see below).
2. The client calls the NetBox REST API with `Authorization: Bearer <access_token>`.
3. NetBox validates the token's signature (against the provider's JWKS), issuer, audience, and expiration.
4. NetBox resolves the token to a user via the same provisioning path used for SSO/remote authentication (`RemoteUserBackend`), honoring the `REMOTE_AUTH_*` settings (auto-create, default groups/permissions, group sync, superuser mapping).
5. The request proceeds under that user, gated by the user's assigned object permissions.

Because native NetBox tokens are also sent using the `Bearer` keyword, NetBox distinguishes the two by token format: any `Bearer` value that is not a well-formed JWT is treated as a native NetBox token and handled by the normal token authentication scheme.

## Configuration parameters

Add the following to `configuration.py`, substituting your own values:

```python
REST_API_OIDC_ENABLED = True
REST_API_OIDC_ISSUER = 'https://login.microsoftonline.com/<tenant-id>/v2.0'
REST_API_OIDC_AUDIENCE = 'api://<application-id>'

# Optional
# REST_API_OIDC_JWKS_URI = None                       # Discovered from the issuer when omitted
# REST_API_OIDC_ALGORITHMS = ['RS256']
# REST_API_OIDC_USERNAME_CLAIM = 'preferred_username'
# REST_API_OIDC_GROUPS_CLAIM = 'groups'
```

| Parameter | Required | Default | Description |
|---|---|---|---|
| `REST_API_OIDC_ENABLED` | — | `False` | Enable OIDC bearer-token authentication for the REST API. |
| `REST_API_OIDC_AUDIENCE` | Yes | `None` | Expected `aud` claim (the NetBox application's ID or App ID URI). Tokens with a different audience are rejected. |
| `REST_API_OIDC_ISSUER` | Yes\* | `None` | Expected `iss` claim; also used to discover the JWKS URI. |
| `REST_API_OIDC_JWKS_URI` | Yes\* | `None` | Explicit JWKS endpoint. Discovered from the issuer's `.well-known/openid-configuration` when omitted. |
| `REST_API_OIDC_ALGORITHMS` | — | `['RS256']` | Permitted signing algorithms. |
| `REST_API_OIDC_USERNAME_CLAIM` | — | `preferred_username` | Claim used as the NetBox username. |
| `REST_API_OIDC_GROUPS_CLAIM` | — | `groups` | Claim (a list) used for group synchronization when `REMOTE_AUTH_GROUP_SYNC_ENABLED` is set. Set to `None` to disable. |

\* At least one of `REST_API_OIDC_ISSUER` or `REST_API_OIDC_JWKS_URI` must be set.

## User provisioning

OIDC-authenticated API users are provisioned identically to SSO/remote-auth users. Set the relevant `REMOTE_AUTH_*` parameters to control behavior:

- `REMOTE_AUTH_AUTO_CREATE_USER = True` — create a NetBox user automatically on first API call. If left `False`, the user must already exist locally.
- `REMOTE_AUTH_DEFAULT_GROUPS` / `REMOTE_AUTH_DEFAULT_PERMISSIONS` — assigned on user creation.
- `REMOTE_AUTH_GROUP_SYNC_ENABLED` — synchronize group membership from the token's groups claim on every request.
- `REMOTE_AUTH_SUPERUSER_GROUPS` / `REMOTE_AUTH_SUPERUSERS` — grant superuser status by group/username.

!!! warning "Group claims"
    Microsoft Entra ID emits the `groups` claim as directory object GUIDs by default, whereas NetBox matches groups by **name**. To use group synchronization, either configure Entra to emit group names / app roles, or create NetBox groups whose names match the emitted GUIDs. See the Entra ID app registration's **Token configuration** options.

## Microsoft Entra ID setup (On-Behalf-Of)

To expose NetBox as a protected API that accepts Entra access tokens:

1. Create an **app registration** for NetBox (or reuse the SSO one).
2. Under **Expose an API**, set the Application ID URI (e.g. `api://<application-id>`) and add a scope (e.g. `user_impersonation`). Use the Application ID URI (or the application ID) as `REST_API_OIDC_AUDIENCE`.
3. Grant the calling (middleware) application permission to that scope so it can perform the On-Behalf-Of exchange.
4. Set `REST_API_OIDC_ISSUER` to `https://login.microsoftonline.com/<tenant-id>/v2.0`.

## Testing

With a valid access token, call any API endpoint:

```no-highlight
curl -H "Authorization: Bearer <access_token>" https://netbox.example.com/api/dcim/sites/
```

A `200` response confirms the token was validated and mapped to a user. A `403` indicates the resolved user lacks the required object permissions; a `401` indicates the token itself could not be validated.

## Troubleshooting

- **`401 Unable to validate token signing key`** — the provider's JWKS could not be retrieved, or the token's `kid` is unknown. Verify `REST_API_OIDC_ISSUER`/`REST_API_OIDC_JWKS_URI` and network access to the provider.
- **`401 Invalid OIDC token`** — signature, `aud`, `iss`, or `exp` validation failed. Confirm the token's audience matches `REST_API_OIDC_AUDIENCE`.
- **`401 ... could not be authenticated`** — the user does not exist and `REMOTE_AUTH_AUTO_CREATE_USER` is disabled.
- **`403`** — authentication succeeded but the user lacks the object permissions for the requested action.

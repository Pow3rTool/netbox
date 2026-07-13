"""
Support for authenticating REST API requests using a JWT access token issued by an external
OpenID Connect provider (e.g. Microsoft Entra ID).

The token is validated against the provider's published signing keys (JWKS) and mapped to a NetBox
user via the same provisioning path used for SSO/remote authentication (see
``netbox.authentication.RemoteUserBackend``). Once resolved, the user's object permissions govern
API access exactly as they would for a session- or token-authenticated request — NetBox performs no
additional authorization based on the token itself.

This module is only exercised when ``REST_API_OIDC_ENABLED`` is set; heavy imports (PyJWT) are
performed lazily so that installations which do not use OIDC incur no import cost.
"""
import logging

from django.conf import settings
from rest_framework import exceptions

logger = logging.getLogger('netbox.api.oidc')

# Module-level caches. PyJWKClient performs its own time-based caching of the fetched JWK set, so we
# retain a single client instance per JWKS URI. The discovery cache maps an issuer to its resolved
# ``jwks_uri`` to avoid repeated fetches of the provider's well-known configuration document.
_jwks_clients = {}
_discovery_cache = {}

__all__ = ('OIDCToken', 'resolve_user', 'validate_jwt')


class OIDCToken:
    """
    Lightweight stand-in for a NetBox ``Token`` used as ``request.auth`` for requests authenticated
    via an external OIDC provider. It carries the validated JWT claims but grants no token-level
    write flag; write access is governed entirely by the authenticated user's object permissions.
    """
    def __init__(self, claims):
        self.claims = claims or {}

    def __repr__(self):
        return f"<OIDCToken sub={self.claims.get('sub')!r}>"

    def __str__(self):
        return self.claims.get('jti') or self.claims.get('sub') or 'oidc-token'


def _discover_jwks_uri(issuer):
    """
    Resolve the JWKS URI for an issuer via its OpenID Connect discovery document, caching the result.
    """
    if issuer in _discovery_cache:
        return _discovery_cache[issuer]

    import requests

    well_known = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    try:
        response = requests.get(well_known, timeout=5)
        response.raise_for_status()
        jwks_uri = response.json()['jwks_uri']
    except (requests.RequestException, KeyError, ValueError) as e:
        logger.error(f"Failed to discover JWKS URI from {well_known}: {e}")
        raise exceptions.AuthenticationFailed("Unable to retrieve OIDC provider configuration.")

    _discovery_cache[issuer] = jwks_uri
    return jwks_uri


def _get_jwks_client():
    """
    Return a cached ``PyJWKClient`` for the configured (or discovered) JWKS URI.
    """
    from jwt import PyJWKClient

    jwks_uri = settings.REST_API_OIDC_JWKS_URI
    if not jwks_uri:
        if not settings.REST_API_OIDC_ISSUER:
            raise exceptions.AuthenticationFailed("OIDC authentication is misconfigured (no issuer or JWKS URI).")
        jwks_uri = _discover_jwks_uri(settings.REST_API_OIDC_ISSUER)

    if jwks_uri not in _jwks_clients:
        _jwks_clients[jwks_uri] = PyJWKClient(jwks_uri)
    return _jwks_clients[jwks_uri]


def validate_jwt(token_str):
    """
    Validate a JWT access token's signature and standard claims, returning the decoded claim set.

    Raises ``rest_framework.exceptions.AuthenticationFailed`` if the token cannot be validated.
    """
    import jwt

    if not settings.REST_API_OIDC_AUDIENCE:
        # Guarded against at settings load, but re-checked here to fail closed rather than skip
        # audience validation.
        raise exceptions.AuthenticationFailed("OIDC authentication is misconfigured (no audience).")

    client = _get_jwks_client()
    try:
        signing_key = client.get_signing_key_from_jwt(token_str)
    except jwt.PyJWTError as e:
        logger.debug(f"Unable to obtain signing key for token: {e}")
        raise exceptions.AuthenticationFailed("Unable to validate token signing key.")

    options = {'require': ['exp']}
    decode_kwargs = {
        'algorithms': settings.REST_API_OIDC_ALGORITHMS,
        'audience': settings.REST_API_OIDC_AUDIENCE,
    }
    if settings.REST_API_OIDC_ISSUER:
        decode_kwargs['issuer'] = settings.REST_API_OIDC_ISSUER
        options['require'].append('iss')

    try:
        claims = jwt.decode(token_str, signing_key.key, options=options, **decode_kwargs)
    except jwt.PyJWTError as e:
        logger.debug(f"Token validation failed: {e}")
        raise exceptions.AuthenticationFailed("Invalid OIDC token.")

    return claims


def resolve_user(request, claims):
    """
    Map validated JWT claims to a NetBox user, provisioning and syncing groups via the same
    ``RemoteUserBackend`` path used for SSO/remote authentication. Honors the ``REMOTE_AUTH_*``
    settings (auto-create, default groups/permissions, group sync, superuser mapping).
    """
    username_claim = settings.REST_API_OIDC_USERNAME_CLAIM
    username = claims.get(username_claim)
    if not username:
        raise exceptions.AuthenticationFailed(f"OIDC token is missing the '{username_claim}' claim.")

    remote_groups = None
    if settings.REST_API_OIDC_GROUPS_CLAIM:
        remote_groups = claims.get(settings.REST_API_OIDC_GROUPS_CLAIM) or []

    # Imported here to avoid a circular import at module load (netbox.authentication imports models).
    from netbox.authentication import RemoteUserBackend

    backend = RemoteUserBackend()
    user = backend.authenticate(request, remote_user=username, remote_groups=remote_groups)
    if user is None:
        raise exceptions.AuthenticationFailed(
            f"OIDC user '{username}' could not be authenticated. It may not exist and "
            "REMOTE_AUTH_AUTO_CREATE_USER may be disabled."
        )

    return user

import hashlib
from importlib import import_module

from django.conf import settings
from django.contrib.auth import get_user
from django.urls import reverse
from django.utils import timezone
from jwcrypto.jwt import JWT

from django_jwt.server.models import Key
from django_jwt.settings_utils import get_setting, get_domain_from_url
from django_jwt.view_utils import calculate_at_hash


def get_value(user, names):
    obj = user
    for name in names:
        obj = getattr(obj, name, None)
        if callable(obj):
            obj = obj()
    return obj


def get_id_token_claims(web, user, scopes, access_token=None, code=None):
    claims = {item.claim: get_value(user, item.attribute_from_user_model.split('.'))
              for item in web.privateclaimswebpage_set.filter(scope__in=scopes)}
    claims.update({'aud': [web.id], 'azp': web.id})
    if access_token is not None:
        claims['at_hash'] = calculate_at_hash(access_token, hashlib.sha256)
    if code is not None:
        claims['c_hash'] = calculate_at_hash(code, hashlib.sha256)
    if claims.get('sub', None) is None:
        claims['sub'] = user.pk
    return claims


def get_access_token_claims(web, user, scopes, jti=None):
    audience = [item.allowed_to.id for item in web.weballowanceotherweb_set.all()]
    audience.append(get_domain_from_url(get_setting('JWT_OIDC.DISCOVERY_ENDPOINT')) + reverse('oidc_userinfo_endpoint'))
    claims = {'aud': audience, 'scope': ' '.join(scopes), 'sub': user.pk}
    if jti is not None:
        claims['jti'] = jti
    return claims


def get_refresh_token_claims(web, user, scopes, external_session):
    audience = [item.allowed_to.id for item in web.weballowanceotherweb_set.all()]
    audience.append(get_domain_from_url(get_setting('JWT_OIDC.DISCOVERY_ENDPOINT')) + reverse('oidc_userinfo_endpoint'))
    claims = {'aud': audience, 'scope': ' '.join(scopes), 'sub': user.pk, 'jti': str(external_session.refresh_token),
              'sid': external_session.id}
    return claims


def create_jwt_code(request, token_type, claims={}, nonce_required=False):
    now = timezone.now()
    token_type = token_type.upper().replace(' ', '_')
    expiration_time = timezone.timedelta(seconds=get_setting('JWT_OIDC.JWT_%s_EXPIRATION_TIME' % token_type))
    jwk = Key.get_actual_jwk()
    claims.update({'iss': get_domain_from_url(get_setting('JWT_OIDC.DISCOVERY_ENDPOINT')),
                   'iat': int(now.timestamp()),
                   'exp': int((now + expiration_time).timestamp())})
    nonce = request.GET.get('nonce', None)
    if nonce_required and nonce is None:
        return None
    elif nonce is not None:
        claims['nonce'] = nonce
    if 'sub' in claims:
        claims['sub'] = str(claims['sub'])
    jwt = JWT(header={'kid': jwk.kid, 'alg': get_setting('JWT_OIDC.SIGNATURE_ALG'), 'typ': 'JWT'},
              claims=claims)
    jwt.make_signed_token(jwk)
    return jwt.serialize()


def get_user_from_request(request, session_id):
    engine = import_module(settings.SESSION_ENGINE)
    request.session = engine.SessionStore(session_id)
    return get_user(request)

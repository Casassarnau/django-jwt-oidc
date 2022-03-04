import hashlib
from datetime import datetime, timedelta

from django.urls import reverse
from jwcrypto.jwt import JWT

from django_jwt.server.models import Key
from django_jwt.settings_utils import get_setting
from django_jwt.view_utils import calculate_at_hash


def get_value(user, names):
    obj = user
    for name in names:
        obj = getattr(obj, name, None)
        if callable(obj):
            obj = obj()
    return obj


def create_jwt_code(request, session, token, access_token=None):
    now = datetime.now()
    expiration_time = timedelta(seconds=get_setting('JWT_SERVER.JWT_EXPIRATION_TIME'))
    jwk = Key.get_actual_jwk()
    if token == 'access_token':
        claims = {'aud': [request.build_absolute_uri(reverse('userinfo_endpoint'))],
                  'azp': session.web.id, 'scope': 'openid profile', 'sub': request.user.pk}
        expiration_time = timedelta(seconds=7200)
    else:
        claims = {'aud': [session.web.id]}
        if access_token is not None:
            claims['at_hash'] = calculate_at_hash(access_token, hashlib.sha256)
        for attribute in session.web.attributewebpage_set.filter(restrict=False):
            claims[attribute.attribute] = get_value(request.user, attribute.value.split('.'))
        if claims.get('sub', None) is None:
            claims['sub'] = request.user.pk
    claims.update({'iss': request.build_absolute_uri('/'),
                   'iat': int(now.timestamp()),
                   'exp': int((now + expiration_time).timestamp()),
                   'nonce': request.GET.get('nonce')})
    jwt = JWT(header={'kid': jwk.kid, 'alg': 'RS256', 'typ': 'JWT'},
              claims=claims)
    jwt.make_signed_token(jwk)
    return jwt.serialize()

from django.conf import settings


class NoDefault:
    pass


JWT_DEFAULT_SETTINGS = {
    # 'JWT_OIDC.DISCOVERY_ENDPOINT': Required
    # 'JWT_OIDC.CLIENT_ID': Required
    # 'JWT_OIDC.TYPE': Required ['fake', 'client', 'provider']
    # 'JWT_OIDC.CLIENT_SECRET': Required if code in RESPONSE_TYPE
    # 'JWT_OIDC.RESPONSE_TYPE': Required
    'JWT_OIDC.ID_TOKEN_RENAME_ATTRIBUTES': {},
    'JWT_OIDC.USER_DEFAULT_ATTRIBUTES': {},
    'JWT_OIDC.CREATE_USER': False,
    'JWT_OIDC.REQUEST_RESPONSE_TYPE': '#',
    'JWT_OIDC.PKCE_EXTENSION': False,
    'JWT_OIDC.CODE_CHALLENGE_METHOD': 'S256',     # ['plain', 'S256'] plain is not supported
    'JWT_OIDC.SCOPE': 'openid',
    'JWT_OIDC.IDENTIFICATION_CLAIM': 'sub',
    'JWT_OIDC.JWK_EXPIRATION_TIME': 3600,
    'JWT_OIDC.JWT_ID_TOKEN_EXPIRATION_TIME': 2700,
    'JWT_OIDC.JWT_ACCESS_TOKEN_EXPIRATION_TIME': 600,
    'JWT_OIDC.JWT_REFRESH_TOKEN_EXPIRATION_TIME': 3600,
    'JWT_OIDC.SIGNATURE_ALG': 'ES512',
    'JWT_OIDC.MAX_REFRESH': 10,
    'JWT_OIDC.USERINFO_SERIALIZER': 'django_jwt.server.serializers.UserSerializer',
    'JWT_OIDC.USERINFO_SERIALIZER_EXCLUDE': ['password'],
    'JWT_OIDC.CLIENT_DISPLAY': None,
    'JWT_OIDC.CLIENT_PROMPT': None,
    'JWT_OIDC.CLIENT_MAX_AGE': None,
    'JWT_OIDC.CLIENT_UI_LOCALES': None,
    'JWT_OIDC.CLIENT_CLAIMS_LOCALES': None,
    'JWT_OIDC.CLIENT_ID_TOKEN_HINT': None,
    'JWT_OIDC.CLIENT_LOGIN_HINT': None,
    'JWT_OIDC.CLIENT_ACR_VALUES': None,
}


JWT_DEFAULT_CONVERTERS = {

}


def get_setting(names):
    default = JWT_DEFAULT_SETTINGS.get(names, NoDefault)
    value = settings
    for name in names.split('.'):
        if isinstance(value, dict):
            value = value.get(name, default)
        else:
            value = getattr(value, name, default)
    if value == NoDefault:
        raise Exception('Setting %s is required' % names)
    converter = JWT_DEFAULT_CONVERTERS.get(names, lambda x: x)
    value = converter(value)
    return value


def get_domain_from_url(url):
    return '/'.join(url.split('/')[0:3])


def get_max_time_token():
    return max([get_setting('JWT_OIDC.JWT_ID_TOKEN_EXPIRATION_TIME'),
                get_setting('JWT_OIDC.JWT_ACCESS_TOKEN_EXPIRATION_TIME'),
                get_setting('JWT_OIDC.JWT_REFRESH_TOKEN_EXPIRATION_TIME')])

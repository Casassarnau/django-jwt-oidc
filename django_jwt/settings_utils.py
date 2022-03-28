from django.conf import settings


class NoDefault:
    pass


JWT_DEFAULT_SETTINGS = {
    'JWT_CLIENT.RENAME_ATTRIBUTES': {},
    'JWT_CLIENT.DEFAULT_ATTRIBUTES': {},
    'JWT_CLIENT.CREATE_USER': False,
    'JWT_CLIENT.COOKIE_NAME': 'id_token',
    'JWT_SERVER.JWK_EXPIRATION_TIME': 3600,
    'JWT_SERVER.JWT_EXPIRATION_TIME': 14400,
    'LOGOUT_URL': 'logout',
}


def convert_url(url):
    if len(url) > 0 and url[-1] == '/':
        url = url[:-1]
    return url


JWT_DEFAULT_CONVERTERS = {
    'JWT_CLIENT.OPENID2_URL': convert_url,
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

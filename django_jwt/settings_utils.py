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
    return value

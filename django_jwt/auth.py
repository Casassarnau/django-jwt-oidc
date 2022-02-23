import json

from django.contrib.auth import get_user_model
from jwcrypto.jwt import JWT, JWTMissingKey

from django_jwt.openid import OpenId2Info
from django_jwt.settings_utils import get_setting


class JWTAuthentication:
    class JWTException(Exception):
        pass

    @classmethod
    def authenticate_credentials(cls, key):
        jwt = cls.validate_jwt(key)
        claims = json.loads(jwt.claims)
        if not cls.verify_claims(claims):
            raise cls.JWTException()
        user, created = cls.get_or_create_user(profile=claims)
        return user

    @classmethod
    def validate_jwt(cls, token, second=False):
        try:
            jwt = JWT(jwt=token, key=OpenId2Info().jwks)
        except JWTMissingKey:
            if second:
                raise cls.JWTException()
            OpenId2Info().fetch_jwks()
            jwt = cls.validate_jwt(token=token, second=True)
        return jwt

    @classmethod
    def get_or_create_user(cls, profile):
        model = get_user_model()
        translation = get_setting('JWT_CLIENT.RENAME_ATTRIBUTES')
        model_fields = [field.name for field in model._meta.get_fields()]
        defaults = get_setting('JWT_CLIENT.DEFAULT_ATTRIBUTES')
        defaults.update({translation.get(key, key): value for key, value in profile.items()
                         if translation.get(key, key) in model_fields})
        for key, value in defaults.items():
            change_field = getattr(model, 'change_%s' % key, None)
            if change_field is not None:
                defaults[key] = change_field(model, value)
        kwargs = {model.USERNAME_FIELD: defaults[model.USERNAME_FIELD]}
        if get_setting('JWT_CLIENT.CREATE_USER'):
            return model.objects.get_or_create(defaults=defaults, **kwargs)
        try:
            return model.objects.get(**kwargs), False
        except model.DoesNotExist:
            return None, False

    @classmethod
    def verify_claims(cls, claims):
        if get_setting('JWT_CLIENT.CLIENT_ID') not in claims.get('aud', []):
            return False
        url = get_setting('JWT_CLIENT.OPENID2_URL')
        if url in ['local', 'fake']:
            url = get_setting('DEFAULT_DOMAIN') + '/'
        iss = claims.get('iss', None)
        if iss is None:
            return False
        if not url.startswith(iss):
            return False
        return True

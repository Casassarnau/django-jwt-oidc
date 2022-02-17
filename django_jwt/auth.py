import json

from django.conf import settings
from django.contrib.auth import get_user_model
from jwcrypto.jwt import JWT, JWTMissingKey

from django_jwt.openid import OpenId2Info


class JWTAuthentication:
    @classmethod
    def authenticate_credentials(cls, key):
        jwt = cls.validate_jwt(key)
        claims = json.loads(jwt.claims)
        user, created = cls.get_or_create_user(profile=claims)
        return user

    @classmethod
    def validate_jwt(cls, token, second=False):
        try:
            jwt = JWT(jwt=token, key=OpenId2Info().jwks)
        except JWTMissingKey:
            if second:
                raise JWTMissingKey()
            OpenId2Info().fetch_jwks()
            jwt = cls.validate_jwt(token=token, second=True)
        return jwt

    @classmethod
    def get_or_create_user(cls, profile):
        model = get_user_model()
        translation = getattr(settings, 'JWT_RENAME_ATTRIBUTES', {})
        model_fields = [field.name for field in model._meta.get_fields()]
        defaults = getattr(settings, 'JWT_DEFAULT_ATTRIBUTES', {})
        defaults.update({translation.get(key, key): value for key, value in profile.items()
                         if translation.get(key, key) in model_fields})
        for key, value in defaults.items():
            change_field = getattr(model, 'change_%s' % key, None)
            if change_field is not None:
                defaults[key] = change_field(model, value)
        kwargs = {model.USERNAME_FIELD: defaults[model.USERNAME_FIELD]}
        if getattr(settings, 'JWT_CREATE_USER', False):
            return model.objects.get_or_create(defaults=defaults, **kwargs)
        try:
            return model.objects.get(**kwargs), False
        except model.DoesNotExist:
            return None, False
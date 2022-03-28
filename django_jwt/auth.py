import json

from django.contrib.auth import get_user_model
from jwcrypto.jwt import JWT, JWTMissingKey

from django_jwt.openid import OpenId2Info
from django_jwt.settings_utils import get_setting


class JWTAuthentication:
    class JWTException(Exception):
        pass

    @classmethod
    def authenticate_credentials(cls, key, nonce=None):
        jwt = cls.validate_jwt(key)
        claims = json.loads(jwt.claims)
        if not cls.verify_claims(claims, nonce):
            raise cls.JWTException('Token is not valid')
        user, created = cls.get_or_create_user(profile=claims)
        return user

    @classmethod
    def validate_jwt(cls, token, second=False):
        try:
            jwt = JWT(jwt=token, key=OpenId2Info().jwks)
        except JWTMissingKey:
            if second:
                raise cls.JWTException('JWK not found')
            OpenId2Info().fetch_jwks()
            jwt = cls.validate_jwt(token=token, second=True)
        except Exception:
            raise cls.JWTException('Token format is not valid or expired')
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
    def verify_claims(cls, claims, nonce=None, client_id=None):
        if client_id is None:
            client_id = get_setting('JWT_CLIENT.CLIENT_ID')
        if client_id not in claims.get('aud', []):
            return False
        url = get_setting('JWT_CLIENT.OPENID2_URL')
        iss = claims.get('iss', None)
        if iss is None:
            return False
        if not url.startswith(iss):
            return False
        if nonce is not None and claims.get('nonce') != nonce:
            return False
        return True

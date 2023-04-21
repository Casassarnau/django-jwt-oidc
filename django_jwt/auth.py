import json
import logging

from django.contrib.auth import get_user_model
from jwcrypto.jwt import JWT, JWTMissingKey, JWTExpired

from django_jwt.openid import OpenId2Info
from django_jwt.settings_utils import get_setting, get_domain_from_url


logger = logging.getLogger(__name__)


class JWTAuthentication:
    class JWTException(Exception):
        pass

    @classmethod
    def authenticate_credentials(cls, key, nonce=None, client_id=None):
        try:
            jwt = cls.validate_jwt(key)
        except Exception as e:
            if isinstance(e, JWTExpired):
                raise e
            logger.warning(e)
            raise cls.JWTException('Token is not valid')
        claims = json.loads(jwt.claims)
        if not cls.verify_claims(claims, nonce, client_id):
            raise cls.JWTException('Token is not valid')
        user, created = cls.get_or_create_user(profile=claims)
        return user, jwt

    @classmethod
    def validate_authorization_jwt(cls, key, nonce=None, sub_attr='pk'):
        try:
            jwt = cls.validate_jwt(key)
        except Exception as e:
            if isinstance(e, JWTExpired):
                raise e
            logger.warning(e)
            raise cls.JWTException('Token is not valid')
        claims = json.loads(jwt.claims)
        if not cls.verify_claims(claims, nonce):
            raise cls.JWTException('Token is not valid')
        model = get_user_model()
        user = None
        try:
            user = model.objects.get(**{sub_attr: claims['sub']})
        except model.DoesNotExist:
            pass
        return user, claims

    @classmethod
    def validate_jwt(cls, token, second=False):
        try:
            jwt = JWT(jwt=token, key=OpenId2Info().jwks)
        except JWTMissingKey:
            if second:
                raise cls.JWTException('JWK not found')
            OpenId2Info().fetch_jwks()
            jwt = cls.validate_jwt(token=token, second=True)
        except ValueError as e:
            logger = logging.getLogger(__name__)
            logger.info(e)
            raise e
        return jwt

    @classmethod
    def get_defaults_from_claims(cls, claims):
        model = get_user_model()
        translation = {'sub': 'pk'}
        translation.update(get_setting('JWT_OIDC.ID_TOKEN_RENAME_ATTRIBUTES'))
        model_fields = [field.name for field in model._meta.get_fields()] + ['pk']
        defaults = get_setting('JWT_OIDC.USER_DEFAULT_ATTRIBUTES')
        defaults.update({translation.get(key, key): value for key, value in claims.items()
                         if translation.get(key, key) in model_fields})
        for key, value in defaults.items():
            change_field = getattr(model, 'change_%s' % key, None)
            if change_field is not None:
                defaults[key] = change_field(model, value)
        claim_id = get_setting('JWT_OIDC.IDENTIFICATION_CLAIM')
        user_id = translation.get(claim_id, claim_id)
        if user_id not in defaults:
            return None, False
        kwargs = {user_id: defaults[user_id]}
        del defaults[user_id]
        return defaults, kwargs

    @classmethod
    def get_or_create_user(cls, profile):
        model = get_user_model()
        defaults, kwargs = cls.get_defaults_from_claims(profile)
        if get_setting('JWT_OIDC.CREATE_USER'):
            return model.objects.get_or_create(defaults=defaults, **kwargs)
        try:
            return model.objects.get(**kwargs), False
        except model.DoesNotExist:
            return None, False

    @classmethod
    def verify_claims(cls, claims, nonce=None, client_id=None):
        openid_domain = get_domain_from_url(get_setting('JWT_OIDC.DISCOVERY_ENDPOINT'))
        if client_id is None and 'django_jwt.server' in get_setting('INSTALLED_APPS'):
            if not any([aud.startswith(openid_domain) for aud in claims.get('aud', [])]):
                return False
        else:
            if client_id is None:
                client_id = get_setting('JWT_OIDC.CLIENT_ID')
            if client_id not in claims.get('aud', []):
                logger.info('Client id not in aud')
                return False
        openid_domain = get_domain_from_url(get_setting('JWT_OIDC.DISCOVERY_ENDPOINT'))
        iss_domain = get_domain_from_url(claims.get('iss', ''))
        # openid_domain can't be '' because of apps.py
        if openid_domain != iss_domain:
            logger.info('Issuer %s is not from OPENID2_URL %s' % (claims.get('iss', ''), openid_domain))
            return False
        if nonce is not None and claims.get('nonce') != nonce:
            logger.info('Nonce changed')
            return False
        return True

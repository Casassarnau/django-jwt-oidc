import logging

from jwcrypto.jwt import JWTExpired
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication
from django.utils.translation import gettext_lazy as _

from django_jwt.auth import JWTAuthentication
from django_jwt.settings_utils import get_setting


class JWTTokenAuthentication(TokenAuthentication):
    keyword = 'Bearer'

    def authenticate_credentials(self, key):
        try:
            user, jwt = JWTAuthentication.authenticate_credentials(key, client_id=get_setting('JWT_OIDC.CLIENT_ID'))
        except (JWTAuthentication.JWTException, JWTExpired) as e:
            logger = logging.getLogger(__name__)
            logger.warning(e)
            raise exceptions.AuthenticationFailed(_('Token is invalid or expired.'))
        if not user:
            raise exceptions.AuthenticationFailed(_('User does not exist.'))
        return user, jwt

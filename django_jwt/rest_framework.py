import logging

from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication
from django.utils.translation import gettext_lazy as _

from django_jwt.auth import JWTAuthentication


class JWTTokenAuthentication(TokenAuthentication):
    keyword = 'Bearer'

    def authenticate_credentials(self, key):
        try:
            user = JWTAuthentication.authenticate_credentials(key)
        except JWTAuthentication.JWTException as e:
            logger = logging.getLogger(__name__)
            logger.warning(e)
            raise exceptions.AuthenticationFailed(_('Token is invalid or expired.'))
        if not user:
            raise exceptions.AuthenticationFailed(_('User does not exist.'))
        return user, key

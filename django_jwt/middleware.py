from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.utils.deprecation import MiddlewareMixin
from jwcrypto.common import JWException

from django_jwt.auth import JWTAuthentication


class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        key = request.COOKIES.get(getattr(settings, 'JWT_COOKIE_NAME', 'token'), None)
        user = None
        if key is not None:
            try:
                user = JWTAuthentication.authenticate_credentials(key)
            except JWException:
                pass
        return user or AnonymousUser()
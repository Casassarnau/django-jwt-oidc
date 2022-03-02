from django.contrib.auth.models import AnonymousUser
from django.utils.deprecation import MiddlewareMixin

from django_jwt.auth import JWTAuthentication
from django_jwt.settings_utils import get_setting


class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        key = request.get_signed_cookie(get_setting('JWT_CLIENT.COOKIE_NAME'), None, salt=get_setting('SECRET_KEY'))
        user = None
        if key is not None:
            try:
                user = JWTAuthentication.authenticate_credentials(key)
            except JWTAuthentication.JWTException:
                pass
        request.user = user or AnonymousUser()

import json
import logging
import types

import urllib3
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from jwcrypto.jwt import JWTExpired

from django_jwt.auth import JWTAuthentication
from django_jwt.openid import OpenId2Info
from django_jwt.settings_utils import get_setting


logger = logging.getLogger(__name__)


class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        id_token = request.session.get('id_token', None)
        claims = None
        user = None
        if id_token is not None:
            try:
                user, jwt_id_token = JWTAuthentication.authenticate_credentials(id_token)
                claims = json.loads(jwt_id_token.claims)
            except JWTExpired:
                self.refresh_token(request)
                user = getattr(request, 'user', None)
                claims = getattr(request, 'user_claims', None)
            except Exception as e:
                logger.error(e)
                pass
        request.user = user or AnonymousUser()
        request.user_claims = claims or {}
        request.userinfo = request.session.get('userinfo', None)
        self.add_get_access_token_to_request(request)

    def add_get_access_token_to_request(self, request):
        def get_access_token(inner_request):
            expiration_date = inner_request.session.get('expiration_date', None)
            access_token = inner_request.session.get('access_token', None)
            if expiration_date is not None and expiration_date < timezone.now():
                self.refresh_token(inner_request)
                access_token = inner_request.session.get('access_token', None)
            try:
                JWTAuthentication.validate_jwt(access_token)
            except ValueError:
                return access_token
            except JWTExpired:
                self.refresh_token(inner_request)
                access_token = inner_request.session.get('access_token', None)
            return access_token
        request.get_access_token = types.MethodType(get_access_token, request)

    def refresh_token(self, request):
        refresh_token = request.session.get('refresh_token', None)
        if refresh_token is None and OpenId2Info().token_endpoint is not None:
            return None
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': request.session.get('refresh_token', None),
            'client_id': get_setting('JWT_OIDC.CLIENT_ID'),
            'client_secret': get_setting('JWT_OIDC.CLIENT_SECRET'),
            'scope': get_setting('JWT_OIDC.SCOPE'),
        }
        headers = {
            'Content-Type': 'application/json',
            'Host': request.get_host(),
        }
        http = urllib3.PoolManager()
        r = http.request('POST', OpenId2Info().token_endpoint, body=json.dumps(data), headers=headers)
        if r.status != 200:
            request.session.flush()
            return None
        response_data = json.loads(r.data.decode('utf-8'))
        if response_data.get('scope', None) and \
                sorted(response_data['scope']) != sorted(get_setting('JWT_OIDC.SCOPE')):
            logger.error('Server returned different scope from configured')
            request.session.flush()
            return None
        refresh_token = response_data.get('refresh_token', None)
        if refresh_token is not None:
            request.session['refresh_token'] = refresh_token
        expires_in = response_data.get('expires_in', None)
        if expires_in is not None:
            request.session['expiration_date'] = timezone.now() + timezone.timedelta(seconds=expires_in)
        id_token = response_data.get('id_token', None)
        if id_token is not None:
            try:
                request.user, jwt_id_token = JWTAuthentication.authenticate_credentials(id_token)
                request.session['id_token'] = id_token
                request.user_claims = json.loads(jwt_id_token.claims)
            except Exception as e:
                logger.warning(e)
                request.user = AnonymousUser()
                request.session.flush()
        access_token = response_data.get('access_token', None)
        if access_token is not None:
            request.session['access_token'] = access_token

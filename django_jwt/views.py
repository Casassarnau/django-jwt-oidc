import hashlib
import json
import logging

import urllib3
from django.core.exceptions import PermissionDenied, BadRequest
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.http import urlencode
from django.views import View

from django_jwt.auth import JWTAuthentication
from django_jwt.openid import OpenId2Info
from django_jwt.settings_utils import get_setting
from django_jwt.view_utils import crear_url_amb_jwt, get_jwks, get_sub_jwt


logger = logging.getLogger(__name__)


class LoginView(View):
    def get(self, request, *args, **kwargs):
        # id_token, access_token, code parameter only gets here from the OIDC response
        if any([request.GET.get(token, None) is not None for token in ['id_token', 'access_token', 'code']]):
            # User logged in, let's capture the Authentication & Authorization response of the OIDC server
            return self.capture_authentication_and_authorization_response()
        # User did not log in, starting Authentication & Authorization request with the OIDC server
        return self.generate_authentication_and_authorization_request()

    def add_optional_parameter_to_dict(self, params, optional_param):
        optional_param_value = get_setting('JWT_OIDC.CLIENT_' + optional_param.title())
        if optional_param_value is not None:
            params[optional_param] = optional_param_value

    def generate_authentication_and_authorization_request(self):
        self.request.session['state'] = get_random_string(32)
        self.request.session['nonce'] = get_random_string(64)
        params = {
            'response_type': get_setting('JWT_OIDC.RESPONSE_TYPE'),
            'client_id': get_setting('JWT_OIDC.CLIENT_ID'),
            'redirect_uri': self.request.build_absolute_uri(),
            'scope': get_setting('JWT_OIDC.SCOPE'),
            'state': self.request.session['state'],
            'nonce': self.request.session['nonce'],
        }
        for optional_param in ['display', 'prompt', 'max_age', 'ui_locales', 'claims_locales', 'id_token_hint',
                               'login_hint', 'acr_values']:
            self.add_optional_parameter_to_dict(params, optional_param)
        if get_setting('JWT_OIDC.PKCE_EXTENSION') and 'code' in get_setting('JWT_OIDC.RESPONSE_TYPE').split(' '):
            self.request.session['code_verifier'] = get_random_string(32)
            params['code_challenge_method'] = get_setting('JWT_OIDC.CODE_CHALLENGE_METHOD')
            if params['code_challenge_method'] == 'S256':
                hasher = hashlib.sha256()
                hasher.update(self.request.session['code_verifier'].encode('utf-8'))
                params['code_challenge'] = hasher.hexdigest()
            else:
                logger.error('Invalid CODE_CHALLENGE_METHOD setting: %s.' % params['code_challenge_method'])
                raise Exception('OpenId error')
        return redirect(OpenId2Info().authorization_endpoint + '?' + urlencode(params))

    def capture_and_verify_token(self, token_name, token=None):
        if token is None:
            token = self.request.GET.get(token_name, None)
        try:
            user, jwt = JWTAuthentication.authenticate_credentials(key=token,
                                                                   nonce=self.request.session.get('nonce', ''))
            if user is None:
                raise PermissionDenied()
            changed = False
            for key, value in JWTAuthentication.get_defaults_from_claims(json.loads(jwt.claims))[0].items():
                if getattr(user, key, None) != value:
                    setattr(user, key, value)
                    changed = True
            if changed:
                user.save()
            self.request.session[token_name] = jwt.serialize()
        except JWTAuthentication.JWTException:
            logger.error('JWT authentication error.')
            return HttpResponseBadRequest('JWT authentication error.')
        return user

    def capture_authorization_flow_response(self, id_token=None, access_token=None):
        data = {
            'grant_type': 'authorization_code',
            'code': self.request.GET.get('code', None),
            'redirect_uri': self.request.build_absolute_uri(),
            'client_id': get_setting('JWT_OIDC.CLIENT_ID'),
            'client_secret': get_setting('JWT_OIDC.CLIENT_SECRET'),
        }
        if get_setting('JWT_OIDC.PKCE_EXTENSION') and 'code' in get_setting('JWT_OIDC.RESPONSE_TYPE').split(' '):
            data['code_verifier'] = self.request.session['code_verifier']
        headers = {
            'Content-Type': 'application/json',
            'Host': self.request.get_host(),
        }
        http = urllib3.PoolManager()
        r = http.request_encode_body('POST', OpenId2Info().token_endpoint, body=json.dumps(data), headers=headers)
        if r.status != 200:
            raise BadRequest('Unauthorized code')
        response_data = json.loads(r.data.decode('utf-8'))
        if response_data.get('scope', None) and \
                sorted(response_data['scope']) != sorted(get_setting('JWT_OIDC.SCOPE')):
            logger.error('Server returned different scope from configured')
            raise BadRequest('State is not the same!')
        refresh_token = response_data.get('refresh_token', None)
        if refresh_token is not None:
            self.request.session['refresh_token'] = refresh_token
        expires_in = response_data.get('expires_in', None)
        if expires_in is not None:
            self.request.session['expiration_date'] = timezone.now() + timezone.timedelta(seconds=expires_in)
        return response_data.get('access_token', access_token), response_data.get('id_token', id_token)

    def capture_authentication_and_authorization_response(self):
        req_state = self.request.GET.get('state', None)
        if req_state is not None and req_state != self.request.session.get('state', None):
            return HttpResponseBadRequest('State modified!')

        response_type_list = get_setting('JWT_OIDC.RESPONSE_TYPE').split(' ')
        access_token = self.request.GET.get('access_token', None)
        id_token = self.request.GET.get('id_token', None)
        if 'code' in response_type_list:
            access_token, id_token = self.capture_authorization_flow_response(access_token=access_token,
                                                                              id_token=id_token)
        if id_token is not None:
            self.capture_and_verify_token(token_name='id_token', token=id_token)
        if access_token is not None:
            try:
                self.request.session['access_token'] = JWTAuthentication.validate_jwt(access_token).serialize()
            except ValueError:
                self.request.session['access_token'] = access_token
            if 'profile' in get_setting('JWT_OIDC.SCOPE') and OpenId2Info().userinfo_endpoint is not None:
                self.get_userinfo(access_token)
        return redirect(self.request.GET.get('next', '/'))

    def get_userinfo(self, access_token):
        headers = {
            'Content-Type': 'application/json',
            'Host': self.request.get_host(),
            'Authorization': 'Bearer %s' % access_token
        }
        http = urllib3.PoolManager()
        r = http.request_encode_body('GET', OpenId2Info().userinfo_endpoint, headers=headers)
        if r.status != 200:
            raise BadRequest('Unauthorized code')
        self.request.session['userinfo'] = json.loads(r.data.decode('utf-8'))


class LogoutView(View):
    def get(self, request, *args, **kwargs):
        redirect_uri = get_setting('LOGOUT_REDIRECT_URL')
        if request.user.is_authenticated and OpenId2Info().end_session_endpoint is not None:
            token = request.session.get('id_token', None)
            params = {'post_logout_redirect_uri': request.build_absolute_uri(redirect_uri), 'id_token_hint': token}
            response = redirect(OpenId2Info().end_session_endpoint + '?' + urlencode(params))
        else:
            response = redirect(redirect_uri)
        request.session.flush()
        return response


def fake_config(request):
    config = {
        'issuer': request.build_absolute_uri('/'),
        'userinfo_endpoint': request.build_absolute_uri(reverse('fake_userinfo')),
        'authorization_endpoint': request.build_absolute_uri(reverse('fake_login')),
        'jwks_uri': request.build_absolute_uri(reverse('fake_jwks')),
        'response_types_supported': ['id_token'],
        'subject_types_supported': ['public'],
        'id_token_signing_alg_values_supported': ['RS256'],
        'claims_supported': ['sub', 'iss', 'aud', 'exp', 'iat', 'jti', 'scope', 'azp'],
        'require_request_uri_registration': True,
    }
    return JsonResponse(config)


def fake_login(request):
    if request.method == 'GET':
        return render(request, "django_jwt/fake_login.html")
    if request.method == 'POST':
        return redirect(crear_url_amb_jwt(request))


def jwks(request):
    return JsonResponse(get_jwks())


def fake_userinfo(request):
    sub = get_sub_jwt(request.headers.get('Authorization').split(' ')[1])
    return JsonResponse({'sub': sub})

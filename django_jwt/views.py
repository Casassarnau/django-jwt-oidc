from django.core.exceptions import PermissionDenied
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import urlencode
from django.views import View

from django_jwt.auth import JWTAuthentication
from django_jwt.openid import OpenId2Info
from django_jwt.settings_utils import get_setting
from django_jwt.view_utils import crear_url_amb_jwt, get_jwks, get_sub_jwt


class LoginView(View):
    def get(self, request, *args, **kwargs):
        id_token = request.GET.get('id_token', None)
        if id_token is None:
            request.session['state'] = get_random_string(16)
            request.session['nonce'] = get_random_string(32)
            params = {
                'client_id': get_setting('JWT_CLIENT.CLIENT_ID'),
                'state': request.session['state'],
                'nonce': request.session['nonce'],
                'redirect_uri': request.build_absolute_uri(),
                'response_type': get_setting('JWT_CLIENT.RESPONSE_TYPE')
            }
            return redirect(OpenId2Info().authorization_endpoint + '?' + urlencode(params))
        req_state = request.GET.get('state', None)
        if req_state is not None and req_state != request.session.get('state', None):
            return HttpResponseBadRequest()
        try:
            user = JWTAuthentication.authenticate_credentials(id_token, nonce=request.session.get('nonce', ''))
        except JWTAuthentication.JWTException:
            return HttpResponseBadRequest()
        if user is None:
            raise PermissionDenied()
        response = redirect(request.GET.get('next', '/'))
        response.set_signed_cookie(get_setting('JWT_CLIENT.COOKIE_NAME'), id_token, salt=get_setting('SECRET_KEY'))
        return response


class LogoutView(View):
    def get(self, request, *args, **kwargs):
        redirect_uri = get_setting('LOGOUT_REDIRECT_URL')
        if request.user.is_authenticated and OpenId2Info().end_session_endpoint is not None:
            token = request.get_signed_cookie(get_setting('JWT_CLIENT.COOKIE_NAME'), None,
                                              salt=get_setting('SECRET_KEY'))
            params = {'post_logout_redirect_uri': request.build_absolute_uri(), 'id_token_hint': token}
            response = redirect(OpenId2Info().end_session_endpoint + '?' + urlencode(params))
            response.delete_cookie(get_setting('JWT_CLIENT.COOKIE_NAME'))
        else:
            response = redirect(redirect_uri)
        response.delete_cookie(get_setting('JWT_CLIENT.COOKIE_NAME'))
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
        return render(request, "fake_login.html")
    if request.method == 'POST':
        return redirect(crear_url_amb_jwt(request))


def jwks(request):
    return JsonResponse(get_jwks())


def fake_userinfo(request):
    sub = get_sub_jwt(request.headers.get('Authorization').split(' ')[1])
    return JsonResponse({'sub': sub})

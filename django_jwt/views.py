from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse

from django_jwt.view_utils import crear_url_amb_jwt, get_jwks, get_sub_jwt


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

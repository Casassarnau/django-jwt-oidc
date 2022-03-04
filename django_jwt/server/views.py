import json

from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import urlencode
from django.views import View
from django.views.generic import TemplateView
from django_jwt.auth import JWTAuthentication

from django_jwt.settings_utils import get_setting

from django_jwt.server.models import WebPage, UserWebPagePermission, UserExternalSession, Key, AttributeWebPage
from django_jwt.server.views_utils import create_jwt_code, get_value


class OpenIdConfiguration(View):
    def get(self, request):
        configuration = {
            'issuer': request.build_absolute_uri('/'),
            'authorization_endpoint': request.build_absolute_uri(reverse('authorization_endpoint')),
            # 'userinfo_endpoint': request.build_absolute_uri(reverse('userinfo_endpoint')),
            'jwks_uri': request.build_absolute_uri(reverse('jwks_uri')),
            'end_session_endpoint': request.build_absolute_uri(reverse('end_session_endpoint')),
            'response_types_supported': ['id_token', 'token'],
            'subject_types_supported': ['public'],
            'id_token_signing_alg_values_supported': ['RS256'],
            'claims_supported': ['sub', 'iss', 'aud', 'exp', 'iat', 'jti', 'scope', 'azp'],
            'require_request_uri_registration': True,
        }
        return JsonResponse(configuration)


class AuthorizationView(LoginRequiredMixin, TemplateView):
    template_name = 'oidc_confirmation.html'

    def get_login_url(self):
        connection = self.request.GET.get('connection', '')
        return super().get_login_url() + (('-' + connection) if connection else '')

    def dispatch(self, request, *args, **kwargs):
        try:
            kwargs['web'] = WebPage.objects.prefetch_related('attributewebpage_set')\
                .get(id=self.request.GET.get('client_id'))
        except WebPage.DoesNotExist:
            raise PermissionDenied()
        redirect_url = self.request.GET.get('redirect_uri', None)
        if redirect_url is None or not redirect_url.startswith(kwargs['web'].host + '/'):
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        web = kwargs.get('web')
        self.check_user_permissions(web)
        if web.needs_confirmation:
            try:
                UserWebPagePermission.objects.get(web=web, user=request.user)
            except UserWebPagePermission.DoesNotExist:
                return render(request, self.template_name, context={'web': web})
        return self.success_response(web)

    def success_response(self, web):
        external_session = UserExternalSession.objects\
            .get_or_create(web=web, session_id=self.request.session.session_key)[0]
        tokens = self.request.GET.get('response_type', None)
        if tokens is None:
            raise SuspiciousOperation("Invalid request; see documentation for correct paramaters")
        tokens = tokens.split(' ')
        response_parameters = {'state': self.request.GET.get('state')}
        if 'token' in tokens:
            response_parameters['access_token'] = create_jwt_code(request=self.request, token='access_token',
                                                                  session=external_session)
        if 'id_token' in tokens:
            response_parameters['id_token'] = create_jwt_code(
                request=self.request, token='id_token', session=external_session,
                access_token=response_parameters.get('access_token', None))
        redirect_uri = self.request.GET.get('redirect_uri')
        if web.response_type in redirect_uri:
            redirect_uri += '&' + urlencode(response_parameters)
        else:
            redirect_uri += web.response_type + urlencode(response_parameters)
        return redirect(redirect_uri)

    def post(self, request, *args, **kwargs):
        web = kwargs.get('web')
        if request.POST.get('confirmation', 'false') == 'true':
            UserWebPagePermission(web=web, user=request.user).save()
            return redirect(request.get_full_path())
        return render(request, self.template_name, context={'web': web, 'denied': True})

    def check_user_permissions(self, web):
        for restrict in web.attributewebpage_set.filter(restrict=True):
            if str(get_value(self.request.user, restrict.attribute.split('.'))) == restrict.value:
                raise PermissionDenied('You don\'t have permission to log in into this web page.')


class JWKsView(View):
    def get(self, request):
        return JsonResponse({'keys': Key.get_jwk_set()})


class LogoutView(View):
    def dispatch(self, request, *args, **kwargs):
        token = request.GET.get('id_token_hint', None)
        redirect_url = self.request.GET.get('post_logout_redirect_uri', '')
        host = '/'.join(redirect_url.split('/')[:3])
        if token is None:
            raise PermissionDenied()
        try:
            kwargs['web'] = WebPage.objects.get(host=host)
        except WebPage.DoesNotExist:
            raise PermissionDenied()
        kwargs['user'] = self.get_user(token, kwargs['web'])
        return super().dispatch(request, *args, **kwargs)

    def get_user(self, token, web):
        try:
            jwt = JWTAuthentication.validate_jwt(token)
        except JWTAuthentication.JWTException:
            raise PermissionDenied()
        claims = json.loads(jwt.claims)
        if not self.check_aud(claims, web):
            raise PermissionDenied()
        if not JWTAuthentication.verify_claims(claims, client_id=web.id):
            raise PermissionDenied()
        try:
            att = web.attributewebpage_set.get(attribute='sub').value.replace('.', '__')
        except AttributeWebPage.DoesNotExist:
            att = 'id'
        kwargs = {att: claims.get('sub')}
        User = get_user_model()
        try:
            return User.objects.get(**kwargs)
        except User.DoesNotExist:
            raise PermissionDenied()

    def check_aud(self, claims, web):
        if isinstance(claims['aud'], str):
            claims['aud'] = [claims['aud']]
        for aud in claims['aud']:
            if aud in [web.host, web.id]:
                return True
        return False

    def get(self, request, *args, **kwargs):
        if kwargs['web'].logout_all and request.user.is_authenticated:
            if kwargs['user'].pk != request.user.pk:
                raise PermissionDenied()
            params = {'next': request.build_absolute_uri()}
            return redirect(reverse(get_setting('LOGOUT_URL')) + '?' + urlencode(params))
        if not kwargs['web'].logout_all:
            UserExternalSession.objects.filter(web=kwargs['web'], session_id=request.session.session_key).delete()
        return redirect(request.GET.get('post_logout_redirect_uri'))

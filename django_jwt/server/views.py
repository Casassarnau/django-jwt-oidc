from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import urlencode
from django.views import View
from django.views.generic import TemplateView

from django_jwt.server.models import WebPage, UserWebPagePermission, UserExternalSession, Key
from django_jwt.server.views_utils import create_jwt_code, get_value


class OpenIdConfiguration(View):
    def get(self, request):
        configuration = {
            'issuer': request.build_absolute_uri('/'),
            'authorization_endpoint': request.build_absolute_uri(reverse('authorization_endpoint')),
            # 'userinfo_endpoint': request.build_absolute_uri(reverse('userinfo_endpoint')),
            'jwks_uri': request.build_absolute_uri(reverse('jwks_uri')),
            # 'end_session_endpoint': request.build_absolute_uri(reverse('end_session_endpoint')),
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
        return redirect(self.request.GET.get('redirect_uri') + '#' + urlencode(response_parameters))

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

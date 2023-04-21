import json
import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import urlencode
from django.utils.module_loading import import_string
from django.views import View
from django.views.generic import TemplateView
from rest_framework import viewsets, mixins
from rest_framework.permissions import IsAuthenticated

from django_jwt.auth import JWTAuthentication
from django_jwt.rest_framework import JWTTokenAuthentication

from django_jwt.settings_utils import get_setting, get_domain_from_url

from django_jwt.server.models import WebPage, UserWebPagePermission, UserExternalSession, Key, PrivateClaimsWebPage, \
    NonceUsed
from django_jwt.server.views_utils import create_jwt_code, get_value, get_id_token_claims, get_access_token_claims, \
    get_refresh_token_claims, get_user_from_request

logger = logging.getLogger(__name__)


class OpenIdConfiguration(View):
    def get(self, request):
        alg_types = [alg_type + alg_size for alg_type in ['RS', 'PS', 'ES'] for alg_size in ['256', '284', '512']]
        configuration = {
            'issuer': request.build_absolute_uri('/'),
            'authorization_endpoint': request.build_absolute_uri(reverse('oidc_authorization_endpoint')),
            'token_endpoint': request.build_absolute_uri(reverse('oidc_token_endpoint')),
            'userinfo_endpoint': request.build_absolute_uri(reverse('oidc_userinfo_endpoint')),
            'jwks_uri': request.build_absolute_uri(reverse('oidc_jwks_endpoint')),
            'end_session_endpoint': request.build_absolute_uri(reverse('oidc_end_session_endpoint')),
            'response_types_supported': ['id_token', 'token', 'code'],
            'subject_types_supported': ['public'],
            'id_token_signing_alg_values_supported': alg_types,
            'claims_supported': ['sub', 'iss', 'aud', 'exp', 'iat', 'jti', 'scope', 'azp', 'sid', 'at_hash', 'c_hash',
                                 'nonce'],
            'require_request_uri_registration': True,
        }
        return JsonResponse(configuration)


class AuthorizationView(LoginRequiredMixin, TemplateView):
    template_name = 'django_jwt/oidc_confirmation.html'

    def get_login_url(self):
        connection = self.request.GET.get('connection', '')
        return super().get_login_url() + (('-' + connection) if connection else '')

    def dispatch(self, request, *args, **kwargs):
        try:
            kwargs['web'] = WebPage.objects.prefetch_related('privateclaimswebpage_set') \
                .get(id=self.request.GET.get('client_id'))
        except WebPage.DoesNotExist:
            raise PermissionDenied()
        redirect_url = self.request.GET.get('redirect_uri', None)
        if redirect_url is None or not redirect_url.startswith(kwargs['web'].host + '/'):
            raise PermissionDenied()
        return super().dispatch(request, *args, **kwargs)

    def prepare_scopes_for_template(self, scopes):
        if 'openid' in scopes:
            scopes.remove('openid')

    def required_to_log_in(self):
        max_age = self.request.GET.get('max_age', None)
        login_date = self.request.session.get('login_date', None)
        max_login_age = timezone.now() - timezone.timedelta(seconds=int(max_age))
        return login_date < max_login_age

    def check_prompt_and_max_age(self):
        prompt = self.request.GET.get('prompt', 'none')
        if (prompt == 'login' and self.request.session.get('oidc_loging_again', None) is None) or \
                self.required_to_log_in():
            self.request.session['oidc_loging_again'] = True
            return redirect(get_setting('LOGIN_URL'))
        if prompt == 'select_account' and self.request.session.get('oidc_select_user', None) is None:
            self.request.session['oidc_select_user'] = True
            return redirect(get_setting('SELECT_USER_URL'))
        return None

    def get(self, request, *args, **kwargs):
        response = self.check_prompt_and_max_age()
        if response is not None:
            return response
        web = kwargs.get('web')
        self.check_user_permissions(web)
        scopes = self.request.GET.get('scope').split(' ')
        if 'openid' not in scopes:
            return SuspiciousOperation("No openid scope found; see documentation for correct parameters")
        not_accepted_scopes, accepted_scopes = UserWebPagePermission.get_not_accepted_and_accepted_scopes(
            user=request.user, web=web, scopes=scopes)
        if self.request.GET.get('prompt', 'none') == 'consent' or len(not_accepted_scopes) != 0:
            self.prepare_scopes_for_template(not_accepted_scopes)
            self.prepare_scopes_for_template(accepted_scopes)
            return render(request, self.template_name, context={'web': web, 'not_accepted_scopes': not_accepted_scopes,
                                                                'accepted_scopes': accepted_scopes})
        return self.success_response(web)

    def success_response(self, web):
        nonce = self.request.GET.get('nonce', None)
        if nonce is not None and NonceUsed.is_used(nonce):
            raise PermissionDenied()
        external_session = UserExternalSession.objects \
            .get_or_create(web=web, session_id=self.request.session.session_key)[0]
        scopes = self.request.GET.get('scope').split(' ')
        tokens = self.request.GET.get('response_type', '').split(' ')
        if len(tokens) == 0:
            raise SuspiciousOperation("Invalid request; see documentation for correct parameters")
        response_type = '#'
        response_parameters = {'state': self.request.GET.get('state')}
        if 'token' in tokens:
            claims = get_access_token_claims(web=web, user=self.request.user, scopes=scopes,
                                             jti=external_session.get_access_token_id())
            response_parameters['access_token'] = create_jwt_code(request=self.request, claims=claims,
                                                                  nonce_required=True, token_type='access_token')
            if response_parameters['access_token'] is None:
                raise SuspiciousOperation("Invalid request; nonce missing! see documentation for correct parameters")
            external_session.access_token_sent = True
        if 'code' in tokens:
            nonce = self.request.GET.get('nonce', None)
            if nonce is not None:
                external_session.nonce = nonce
            response_parameters['code'] = external_session.get_authorization_code()
            response_type = '?'
            external_session.scopes = ' '.join(scopes)
        if 'id_token' in tokens:
            claims = get_id_token_claims(web=web, user=self.request.user, scopes=scopes,
                                         access_token=response_parameters.get('access_token', None),
                                         code=response_parameters.get('code', None))
            response_parameters['id_token'] = create_jwt_code(request=self.request, claims=claims, nonce_required=True,
                                                              token_type='id_token')
            if response_parameters['id_token'] is None:
                raise SuspiciousOperation("Invalid request; nonce missing! see documentation for correct parameters")
            external_session.id_token_sent = True
        redirect_uri = self.request.GET.get('redirect_uri')
        external_session.save()
        if response_type in redirect_uri:
            redirect_uri += '&' + urlencode(response_parameters)
        else:
            redirect_uri += response_type + urlencode(response_parameters)
        return redirect(redirect_uri)

    def post(self, request, *args, **kwargs):
        web = kwargs.get('web')
        if request.POST.get('confirmation', 'false') == 'true':
            scopes = self.request.GET.get('scope').split(' ')
            UserWebPagePermission.update_accepted_scopes(user=request.user, web=web, scopes=scopes)
            return redirect(request.get_full_path())
        return render(request, self.template_name, context={'web': web, 'denied': True})

    def check_user_permissions(self, web: WebPage):
        for restrict in web.restrictuserstoweb_set.all():
            if str(get_value(self.request.user, restrict.attribute_from_user_model.split('.'))) == restrict.value:
                raise PermissionDenied('You don\'t have permission to log in into this web page.')


class TokenView(View):
    def check_client_secret(self):
        try:
            web = WebPage.objects.prefetch_related('privateclaimswebpage_set') \
                .get(id=self.request.POST.get('client_id', None))
        except WebPage.DoesNotExist:
            raise PermissionDenied()
        client_secret = self.request.POST.get('client_secret', None)
        if client_secret is not None and web.client_secret != client_secret:
            raise PermissionDenied()
        return web

    def authorization_code_response(self, web):
        code_verifier = self.request.POST.get('code_verifier', None)
        if self.request.POST.get('client_secret', None) is None and code_verifier is None:
            raise PermissionDenied()
        external_session = UserExternalSession.check_authorization_code(self.request.POST.get('code', None))
        if external_session is None:
            raise PermissionDenied()
        if code_verifier is not None and external_session.check_code_challenge(code_verifier):
            raise PermissionDenied()
        user = get_user_from_request(request=self.request, session_id=external_session.session_id)
        scopes = external_session.scopes.split(' ')
        external_session.access_token_sent = external_session.id_token_sent = False
        response_object = self.create_tokens(web=web, user=user, external_session=external_session, scopes=scopes,
                                             access_token=not external_session.access_token_sent,
                                             id_token=not external_session.id_token_sent)
        response_object.update({'token_type': 'Bearer'})
        return JsonResponse(response_object)

    def add_optional_nonce(self, claims, external_session):
        if external_session.nonce != '':
            claims['nonce'] = external_session.nonce

    def create_tokens(self, web, user, external_session, scopes, access_token=True, id_token=True):
        response_object = {}
        if access_token:
            claims = get_access_token_claims(web=web, user=user, scopes=scopes,
                                             jti=external_session.get_access_token_id())
            self.add_optional_nonce(claims, external_session)
            response_object['access_token'] = create_jwt_code(request=self.request, claims=claims,
                                                              token_type='access_token')
            external_session.access_token_sent = True
        if id_token:
            claims = get_id_token_claims(web=web, user=user, scopes=scopes,
                                         access_token=response_object.get('access_token', None),
                                         code=self.request.POST.get('code', None))
            self.add_optional_nonce(claims, external_session)
            response_object['id_token'] = create_jwt_code(request=self.request, claims=claims, token_type='id_token')
            external_session.id_token_sent = True
        external_session.nonce = ''
        external_session.save()
        claims = get_refresh_token_claims(web=web, user=user, scopes=scopes, external_session=external_session)
        response_object['refresh_token'] = create_jwt_code(request=self.request, claims=claims,
                                                           token_type='refresh_token')
        return response_object

    def refresh_token_response(self, web: WebPage):
        try:
            sub_attr = web.privateclaimswebpage_set.get(claim='sub').attribute_from_user_model.replace('.', '__')
        except PrivateClaimsWebPage.DoesNotExist:
            sub_attr = 'pk'
        user, claims = JWTAuthentication.validate_authorization_jwt(key=self.request.POST.get('refresh_token', None),
                                                                    sub_attr=sub_attr)
        scopes = claims.get('scope', '').split(' ')
        try:
            external_session = UserExternalSession.objects.get(id=claims.get('sid', None))
        except UserExternalSession.DoesNotExist:
            raise PermissionDenied()
        if str(external_session.refresh_token) != str(claims.get('jti', 0)):
            external_session.delete()
            raise PermissionDenied()
        max_refresh = get_setting('JWT_OIDC.MAX_REFRESH')
        if max_refresh is not None and external_session.refresh_token >= max_refresh:
            raise PermissionDenied()
        external_session.refresh_token += 1
        external_session.save()
        response_object = self.create_tokens(web=web, user=user, external_session=external_session, scopes=scopes)
        return JsonResponse(response_object)

    def post(self, request, *args, **kwargs):
        self.request.POST = json.loads(request.body.decode('utf-8'))
        web = self.check_client_secret()
        grant_type = self.request.POST.get('grant_type', None)
        if grant_type == 'refresh_token':
            return self.refresh_token_response(web)
        elif grant_type == 'authorization_code':
            return self.authorization_code_response(web)
        raise SuspiciousOperation("Invalid request; see documentation for correct parameters")


class JWKsView(View):
    def get(self, request):
        return JsonResponse({'keys': Key.get_jwk_set()})


class LogoutView(View):
    def dispatch(self, request, *args, **kwargs):
        token = request.GET.get('id_token_hint', None)
        redirect_url = self.request.GET.get('post_logout_redirect_uri', '')
        host = get_domain_from_url(redirect_url)
        if token is None:
            raise PermissionDenied()
        try:
            kwargs['web'] = WebPage.objects.get(host=host)
        except WebPage.DoesNotExist:
            raise PermissionDenied()
        try:
            kwargs['user'] = JWTAuthentication.authenticate_credentials(token, client_id=kwargs['web'].id)[0]
        except Exception as e:
            logger.warning(e)
        return super().dispatch(request, *args, **kwargs)

    def get_user(self, token, web: WebPage):
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
            att = web.privateclaimswebpage_set.get(claim='sub').attribute_from_user_model.replace('.', '__')
        except PrivateClaimsWebPage.DoesNotExist:
            att = 'pk'
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
        if kwargs['web'].logout_all:
            if request.user.is_authenticated and kwargs.get('user', None) is not None:
                if kwargs['user'].pk != request.user.pk:
                    raise PermissionDenied()
            else:
                UserExternalSession.objects.filter(session_id=request.session.session_key).delete()
            request.session.flush()
        if not kwargs['web'].logout_all:
            UserExternalSession.objects.filter(web=kwargs['web'], session_id=request.session.session_key).delete()
        return redirect(request.GET.get('post_logout_redirect_uri'))


class UserInfoViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    authentication_classes = [JWTTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        return import_string(get_setting('JWT_OIDC.USERINFO_SERIALIZER'))

    def get_object(self):
        return self.request.user

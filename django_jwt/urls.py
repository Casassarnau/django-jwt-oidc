from django.urls import path, include

from django_jwt import views
from django_jwt.settings_utils import get_setting

urlpatterns = []

if get_setting('JWT_OIDC.TYPE') == 'fake':
    urlpatterns.extend([
        path('jwks', views.jwks, name="fake_jwks"),
        path('fake-login', views.fake_login, name="fake_login"),
        path('.well-known/openid-configuration', views.fake_config, name='fake_config'),
        path('fake-userinfo', views.fake_userinfo, name='fake_userinfo'),
    ])

elif get_setting('JWT_OIDC.TYPE') == 'client':
    urlpatterns.extend([
        path('login', views.LoginView.as_view(), name='oidc_login'),
        path('logout', views.LogoutView.as_view(), name='oidc_logout'),
    ])

elif get_setting('JWT_OIDC.TYPE') == 'provider':
    urlpatterns.extend([
        path('', include('django_jwt.server.urls'))
    ])

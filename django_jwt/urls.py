from django.urls import path

from django_jwt import views
from django_jwt.settings_utils import get_setting

urlpatterns = [
    path('login', views.LoginView.as_view(), name='oidc_login'),
    path('logout', views.LogoutView.as_view(), name='oidc_logout'),
]

if get_setting('JWT_CLIENT.TYPE') == 'fake':
    urlpatterns.extend([
        path('jwks', views.jwks, name="fake_jwks"),
        path('fake-login', views.fake_login, name="fake_login"),
        path('.well-known/openid-configuration', views.fake_config, name='fake_config'),
        path('fake-userinfo', views.fake_userinfo, name='fake_userinfo'),
    ])

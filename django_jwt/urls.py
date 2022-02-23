from django.urls import path

from django_jwt import views
from django_jwt.settings_utils import get_setting

urlpatterns = []

if get_setting('JWT_CLIENT.OPENID2_URL') == 'fake':
    urlpatterns.extend([
        path('jwks', views.jwks, name="fake_jwks"),
        path('fake-login', views.fake_login, name="fake_login"),
        path('.well-known/openid-configuration', views.fake_config, name='fake_config'),
        path('fake-userinfo', views.fake_userinfo, name='fake_userinfo'),
    ])

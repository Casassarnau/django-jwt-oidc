from django.conf import settings
from django.urls import path

from django_jwt import views

urlpatterns = []

if getattr(settings, 'JWT_OPENID2_URL', None) == 'local':
    urlpatterns.extend([
        path('jwks', views.jwks, name="fake_jwks"),
        path('fake-login', views.fake_login, name="fake_login"),
        path('.well-known/openid-configuration', views.fake_config, name='fake_config'),
        path('fake-userinfo', views.fake_userinfo, name='fake_userinfo'),
    ])

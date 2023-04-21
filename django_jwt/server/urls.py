from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from django_jwt.server import views

urlpatterns = [
    path('jwks', views.JWKsView.as_view(), name="oidc_jwks_endpoint"),
    path('authenticate', views.AuthorizationView.as_view(), name="oidc_authorization_endpoint"),
    path('.well-known/openid-configuration', views.OpenIdConfiguration.as_view(), name='oidc_discovery_endpoint'),
    path('userinfo', views.UserInfoViewSet.as_view({'get': 'retrieve'}), name='oidc_userinfo_endpoint'),
    path('logout', views.LogoutView.as_view(), name='oidc_end_session_endpoint'),
    path('token', csrf_exempt(views.TokenView.as_view()), name='oidc_token_endpoint'),
]

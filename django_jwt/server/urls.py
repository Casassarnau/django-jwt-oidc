from django.urls import path

from django_jwt.server import views

urlpatterns = [
    path('jwks', views.JWKsView.as_view(), name="jwks_uri"),
    path('authenticate', views.AuthorizationView.as_view(), name="authorization_endpoint"),
    path('.well-known/openid-configuration', views.OpenIdConfiguration.as_view(), name='oidc_config'),
    # path('userinfo', None, name='userinfo_endpoint'),
    path('logout', views.LogoutView.as_view(), name='end_session_endpoint'),
]

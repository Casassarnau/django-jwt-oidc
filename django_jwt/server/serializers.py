from django.contrib.auth import get_user_model
from rest_framework import serializers

from django_jwt.settings_utils import get_setting


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        exclude = get_setting('JWT_OIDC.USERINFO_SERIALIZER_EXCLUDE')

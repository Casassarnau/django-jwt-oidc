from django.apps import AppConfig

from django_jwt.settings_utils import get_setting


class DjangoJwtConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_jwt'

    def ready(self):
        client_type = get_setting('JWT_CLIENT.TYPE')
        if client_type == 'local':
            apps = get_setting('INSTALLED_APPS')
            if 'django_jwt.server' not in apps:
                raise Exception('You need to add django_jwt.server into your INSTALLED_APPS in order to deploy the '
                                'OpenId server')

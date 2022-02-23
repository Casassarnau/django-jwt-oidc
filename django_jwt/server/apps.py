from django.apps import AppConfig

from django_jwt.settings_utils import get_setting


class DjangoJwtServerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_jwt.server'

    def ready(self):
        apps = get_setting('INSTALLED_APPS')
        if 'corsheaders' in apps:
            from django_jwt.server import signals
            signals
        else:
            raise Exception('corsheaders is required in order to protect your app from CORS')

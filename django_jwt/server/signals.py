from corsheaders.signals import check_request_enabled

from django_jwt.server.models import WebPage


def cors_allow_webpages(sender, request, **kwargs):
    origin = request.META.get('HTTP_ORIGIN', None)
    if origin is not None:
        return WebPage.objects.filter(host=origin).exists()


check_request_enabled.connect(cors_allow_webpages)

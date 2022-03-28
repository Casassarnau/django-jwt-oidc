from datetime import datetime, timedelta
from Crypto.PublicKey import RSA

import uuid

from Crypto.Util.py3compat import tobytes
from django.conf import settings
from django.contrib.sessions.models import Session
from django.db import models
from jwcrypto.jwk import JWK

from django_jwt.settings_utils import get_setting


def generate_key():
    private_key = RSA.generate(2048)
    return private_key.export_key(passphrase=get_setting('SECRET_KEY'))


class Key(models.Model):
    kid = models.CharField(primary_key=True, default=uuid.uuid4, editable=False, max_length=40)
    private_key = models.BinaryField(editable=False, default=generate_key)
    date = models.DateTimeField(default=datetime.now, editable=False)

    def to_jwk(self):
        jwk = JWK()
        jwk.import_from_pem(self.private_key, kid=str(self.kid), password=tobytes(get_setting('SECRET_KEY')))
        return jwk

    @classmethod
    def get_actual_jwk(cls):
        now = datetime.now()
        expiration_time = timedelta(seconds=get_setting('JWT_SERVER.JWK_EXPIRATION_TIME'))
        try:
            key = cls.objects.get(date__gt=(now - expiration_time))
        except cls.DoesNotExist:
            key = cls()
            key.save()
        except cls.MultipleObjectsReturned:
            key = cls.objects.filter(date__gt=(now - expiration_time)).order('-date').first()
        return key.to_jwk()

    @classmethod
    def get_jwk_set(cls):
        now = datetime.now()
        expiration_time = timedelta(seconds=get_setting('JWT_SERVER.JWT_EXPIRATION_TIME'))
        cls.objects.filter(date__lt=(now - expiration_time - timedelta(hours=1))).delete()
        keys = cls.objects.all()
        return [key.to_jwk().export_public(as_dict=True) for key in keys]


class WebPage(models.Model):
    RESPONSE_PARAMS = '?'
    RESPONSE_HASH = '#'
    RESPONSE_TYPES = [
        (RESPONSE_HASH, 'Hash'),
        (RESPONSE_PARAMS, 'Params')
    ]

    id = models.CharField(primary_key=True, default=uuid.uuid4, editable=False, max_length=40, verbose_name='Client id')
    host = models.CharField(unique=True, max_length=200)
    needs_confirmation = models.BooleanField(default=True)
    logout_all = models.BooleanField(default=True)
    response_type = models.CharField(max_length=1, choices=RESPONSE_TYPES, default=RESPONSE_HASH)

    def __str__(self):
        return self.host


class AttributeWebPage(models.Model):
    web = models.ForeignKey(WebPage, on_delete=models.CASCADE)
    attribute = models.CharField(max_length=100)
    value = models.CharField(max_length=100)
    restrict = models.BooleanField(default=False)

    def __str__(self):
        return 'ID: %s - %s - %s' % (self.id, self.attribute, self.value)


class UserExternalSession(models.Model):
    id = models.CharField(primary_key=True, default=uuid.uuid4, editable=False, max_length=40)
    extra_id = models.CharField(default=uuid.uuid4, unique=True, max_length=40)
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    web = models.ForeignKey(WebPage, on_delete=models.CASCADE)
    date = models.DateTimeField(auto_now_add=True)


class UserWebPagePermission(models.Model):
    web = models.ForeignKey(WebPage, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

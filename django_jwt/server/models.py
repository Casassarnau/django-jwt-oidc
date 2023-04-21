import base64
import hashlib
import json

from Crypto.PublicKey import RSA, ECC

import uuid

from Crypto.Util.py3compat import tobytes
from django.conf import settings
from django.contrib.sessions.models import Session
from django.db import models
from django.utils import timezone
from jwcrypto.jwk import JWK

from django_jwt.settings_utils import get_setting, get_max_time_token


def generate_key():
    alg = get_setting('JWT_OIDC.SIGNATURE_ALG')
    if alg[:2] in ['RS', 'PS']:
        private_key = RSA.generate(2048)
        return tobytes(private_key.export_key(passphrase=get_setting('SECRET_KEY')))
    # ECC
    curve = alg[2:]
    if curve == '512':
        curve = '521'
    private_key = ECC.generate(curve='p%s' % curve)
    return tobytes(private_key.export_key(format='PEM', passphrase=get_setting('SECRET_KEY'),
                                          protection='PBKDF2WithHMAC-SHA1AndAES128-CBC'))


class Key(models.Model):
    kid = models.CharField(primary_key=True, default=uuid.uuid4, editable=False, max_length=40)
    private_key = models.BinaryField(editable=False, default=generate_key)
    date = models.DateTimeField(default=timezone.now, editable=False)

    def to_jwk(self):
        jwk = JWK()
        jwk.import_from_pem(tobytes(self.private_key), kid=str(self.kid), password=tobytes(get_setting('SECRET_KEY')))
        return jwk

    @classmethod
    def get_actual_jwk(cls):
        now = timezone.now()
        expiration_time = timezone.timedelta(seconds=get_setting('JWT_OIDC.JWK_EXPIRATION_TIME'))
        try:
            key = cls.objects.get(date__gt=(now - expiration_time))
        except cls.DoesNotExist:
            key = cls()
            key.save()
        except cls.MultipleObjectsReturned:
            key = cls.objects.filter(date__gt=(now - expiration_time)).order_by('-date').first()
        return key.to_jwk()

    @classmethod
    def get_jwk_set(cls):
        now = timezone.now()
        key_expiration_time = timezone.timedelta(seconds=get_setting('JWT_OIDC.JWK_EXPIRATION_TIME'))
        max_token_expiration_time = timezone.timedelta(seconds=get_max_time_token() + 120)
        cls.objects.filter(date__lt=(now - key_expiration_time - max_token_expiration_time)).delete()
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
    client_secret = models.CharField(default=uuid.uuid4, editable=False, max_length=40)
    host = models.CharField(unique=True, max_length=200)
    logout_all = models.BooleanField(default=True)
    name = models.CharField(blank=True, max_length=100)
    logo = models.ImageField(blank=True, upload_to='django_jwt_oidc')

    def get_logo_as_base64(self, format='png'):
        if self.logo == '' or self.logo is None:
            return ''
        image = self.logo.open(mode='rb')
        encoded_string = base64.b64encode(image.read()).decode('utf-8')
        return 'data:image/%s;base64,%s' % (format, encoded_string)

    def __str__(self):
        return self.host

    def get_name(self):
        if self.name != '':
            return self.name
        return self.host


class PrivateClaimsWebPage(models.Model):
    web = models.ForeignKey(WebPage, on_delete=models.CASCADE)
    attribute_from_user_model = models.CharField(max_length=100, help_text='You can use methods without "()" and use '
                                                                           '"." to get an attribute inside another'
                                                                           ' one.')
    claim = models.CharField(max_length=100, help_text="Claim name. Example: sub, etc.")
    scope = models.CharField(max_length=100, help_text="Extra claim to warn user about what data is being used. "
                                                       "Ex: email, profile, etc.")


class RestrictUsersToWeb(models.Model):
    web = models.ForeignKey(WebPage, on_delete=models.CASCADE)
    attribute_from_user_model = models.CharField(max_length=100, help_text='You can use methods without "()" and use '
                                                                           '"." to get an attribute inside another'
                                                                           ' one.')
    value = models.CharField(max_length=100, help_text='If the user has the same value as this, it won\'t '
                                                       'log in into this web page.')


class UserExternalSession(models.Model):
    id = models.CharField(primary_key=True, default=uuid.uuid4, editable=False, max_length=40)
    access_token_id = models.CharField(default=uuid.uuid4, unique=True, max_length=40)
    authorization_code = models.CharField(blank=True, max_length=40)
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    web = models.ForeignKey(WebPage, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(default=timezone.now)
    refresh_token = models.IntegerField(default=1)
    code_challenge = models.TextField(blank=True, max_length=100)
    nonce = models.TextField(blank=True, max_length=100)
    id_token_sent = models.BooleanField(default=False)
    access_token_sent = models.BooleanField(default=False)
    scopes = models.TextField(blank=True)

    def get_access_token_id(self):
        self.access_token_id = uuid.uuid4()
        return str(self.access_token_id)

    def get_authorization_code(self):
        self.authorization_code = uuid.uuid4()
        return str(self.authorization_code)

    @classmethod
    def check_authorization_code(cls, code):
        try:
            instance = cls.objects.get(authorization_code=code)
        except cls.DoesNotExist:
            return None
        instance.authorization_code = ''
        instance.save()
        return instance

    def set_code_challenge(self, code_challenge, code_challenge_method):
        self.code_challenge = '%s$%s' % (code_challenge_method, code_challenge)

    def check_code_challenge(self, code_verifier):
        if self.code_challenge == '':
            return False
        alg, digested_hash = self.code_challenge.split('$')
        if alg == 'S256':
            hasher = hashlib.sha256()
            hasher.update(code_verifier.encode('utf-8'))
            return hasher.hexdigest() == digested_hash
        return False

    class Meta:
        unique_together = ('session', 'web')


class WebAllowanceOtherWeb(models.Model):
    web = models.ForeignKey(WebPage, on_delete=models.CASCADE)
    allowed_to = models.ForeignKey(WebPage, on_delete=models.CASCADE, related_name='allowed_on')


class UserWebPagePermission(models.Model):
    web = models.ForeignKey(WebPage, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    scopes_json = models.TextField()

    @classmethod
    def get_not_accepted_and_accepted_scopes(cls, user, web, scopes):
        try:
            instance = cls.objects.get(user=user, web=web)
        except cls.DoesNotExist:
            return scopes, []
        accepted_scopes = instance.scopes
        not_accepted_scopes = [item for item in scopes if item not in accepted_scopes]
        return not_accepted_scopes, accepted_scopes

    @classmethod
    def update_accepted_scopes(cls, user, web, scopes):
        instance = cls.objects.get_or_create(user=user, web=web)[0]
        instance.scopes = scopes
        instance.save()

    @property
    def scopes(self):
        try:
            return json.loads(self.scopes_json)
        except json.JSONDecodeError:
            return []

    @scopes.setter
    def scopes(self, scopes):
        self.scopes_json = json.dumps(scopes)


class NonceUsed(models.Model):
    nonce = models.CharField(max_length=100)
    issued_at = models.DateTimeField(default=timezone.now)

    @classmethod
    def is_used(cls, nonce):
        now = timezone.now()
        key_expiration_time = timezone.timedelta(seconds=get_setting('JWT_OIDC.JWK_EXPIRATION_TIME'))
        max_token_expiration_time = timezone.timedelta(seconds=get_max_time_token() + 120)
        return cls.objects.filter(issued_at__gt=(now - key_expiration_time - max_token_expiration_time),
                                  nonce=nonce).exists()

    @classmethod
    def delete_nonce(cls):
        now = timezone.now()
        key_expiration_time = timezone.timedelta(seconds=get_setting('JWT_OIDC.JWK_EXPIRATION_TIME'))
        max_token_expiration_time = timezone.timedelta(seconds=get_max_time_token() + 120)
        cls.objects.filter(issued_at__lt=(now - key_expiration_time - max_token_expiration_time)).delete()

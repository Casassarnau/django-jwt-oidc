import json

import urllib3
from django.conf import settings
from django.urls import reverse
from jwcrypto.jwk import JWKSet

from django_jwt.exceptions import JWTClientException


# singleton class that saves all information from the OpenId server
class OpenId2Info:
    def __init__(self):
        url = getattr(settings, 'JWT_OPENID2_URL', None)
        if url is None:
            raise JWTClientException('JWT_OPENID2_URL not set')
        if url == 'local':
            url = getattr(settings, 'DEFAULT_DOMAIN', 'http:localhost:8000') + reverse('fake_config')
        else:
            url += '/.well-known/openid-configuration'

        # Getting urls info from OpenId server
        http = urllib3.PoolManager()
        r = http.request('GET', url)
        if r.status != 200:
            raise JWTClientException('OpenID returned error code %s on openid-configuration: %s' % (r.status, url))
        data = json.loads(r.data.decode('UTF-8'))
        self.jwks_uri = data.get('jwks_uri', None)
        if self.jwks_uri is None:
            raise JWTClientException('jkws_uri not found in OpenId openid-configuration url')
        self.fetch_jwks()

    # Updates all the actual JWKS from the OPenId server
    def fetch_jwks(self):
        http = urllib3.PoolManager()
        r = http.request('GET', self.jwks_uri)
        if r.status != 200:
            raise JWTClientException('OpenID returned error code %s on jwks_uri: %s' % (r.status, self.jwks_uri))
        self.jwks = JWKSet.from_json(r.data.decode('UTF-8'))

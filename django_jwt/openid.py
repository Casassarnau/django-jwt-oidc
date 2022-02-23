import json

import urllib3
from django.urls import reverse
from jwcrypto.jwk import JWKSet

from django_jwt.exceptions import JWTClientException
from django_jwt.settings_utils import get_setting


# singleton class that saves all information from the OpenId server
class OpenId2Info:
    def __init__(self):
        url = get_setting('JWT_CLIENT.OPENID2_URL')
        if url == 'local':
            apps = get_setting('INSTALLED_APPS')
            if 'django_jwt.server' not in apps:
                raise JWTClientException('JWT_CLIENT.OPENID2_URL not set or django_jwt.server not installed')
            url = get_setting('DEFAULT_DOMAIN') + reverse('oidc_config')
        elif url == 'fake':
            url = get_setting('DEFAULT_DOMAIN') + reverse('fake_config')
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

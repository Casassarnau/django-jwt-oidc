import json
import logging

import urllib3
from jwcrypto.jwk import JWKSet

from django_jwt.exceptions import JWTClientException
from django_jwt.settings_utils import get_setting


# singleton class that saves all information from the OpenId server
class OpenId2Info:
    def __init__(self):
        url = get_setting('JWT_CLIENT.OPENID2_URL')
        client_type = get_setting('JWT_CLIENT.TYPE')
        if client_type == 'local':
            apps = get_setting('INSTALLED_APPS')
            if 'django_jwt.server' not in apps:
                raise JWTClientException('django_jwt.server not installed for type local')
        url += '/.well-known/openid-configuration'

        # Getting urls info from OpenId server
        http = urllib3.PoolManager()
        r = http.request('GET', url)
        if r.status != 200:
            error_message = 'OpenID returned error code %s on openid-configuration: %s' % (r.status, url)
            logger = logging.getLogger(__name__)
            logger.critical(error_message)
            raise JWTClientException(error_message)
        data = json.loads(r.data.decode('UTF-8'))
        self.jwks_uri = data.get('jwks_uri', None)
        self.authorization_endpoint = data.get('authorization_endpoint', None)
        self.end_session_endpoint = data.get('end_session_endpoint', None)
        if self.jwks_uri is None or self.authorization_endpoint is None:
            raise JWTClientException('jkws_uri or authorization_endpoint not found in OpenId openid-configuration url')
        self.fetch_jwks()

    # Updates all the actual JWKS from the OPenId server
    def fetch_jwks(self):
        http = urllib3.PoolManager()
        r = http.request('GET', self.jwks_uri)
        if r.status != 200:
            error_message = 'OpenID returned error code %s on jwks_uri: %s' % (r.status, self.jwks_uri)
            logger = logging.getLogger(__name__)
            logger.critical(error_message)
            raise JWTClientException(error_message)
        self.jwks = JWKSet.from_json(r.data.decode('UTF-8'))

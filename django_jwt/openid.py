import json
import logging

import urllib3
from jwcrypto.jwk import JWKSet

from django_jwt.exceptions import JWTClientException
from django_jwt.patterns import Singleton
from django_jwt.settings_utils import get_setting


# singleton class that saves all information from the OpenId server
class OpenId2Info(metaclass=Singleton):
    def __init_local__(self):
        apps = get_setting('INSTALLED_APPS')
        if 'django_jwt.server' not in apps:
            raise JWTClientException('django_jwt.server not installed for type local')

    def __init_remote__(self):
        url = get_setting('JWT_OIDC.DISCOVERY_ENDPOINT')
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
        self.token_endpoint = data.get('token_endpoint', None)
        self.authorization_endpoint = data.get('authorization_endpoint', None)
        self.end_session_endpoint = data.get('end_session_endpoint', None)
        self.userinfo_endpoint = data.get('userinfo_endpoint', None)
        if self.jwks_uri is None or self.authorization_endpoint is None:
            raise JWTClientException('jkws_uri or authorization_endpoint not found in OpenId openid-configuration url')

    def __init__(self):
        self.jwks_uri = None
        self.authorization_endpoint = None
        self.end_session_endpoint = None
        self.jwks = None
        self.userinfo_endpoint = None
        self.client_type = get_setting('JWT_OIDC.TYPE')
        if self.client_type == 'provider':
            self.__init_local__()
        elif self.client_type == 'client':
            self.__init_remote__()
        self.fetch_jwks()

    # Updates all the actual JWKS from the OPenId server
    def fetch_jwks(self):
        logger = logging.getLogger(__name__)
        logger.info('Fetching JWKs')
        if self.client_type == 'client':
            http = urllib3.PoolManager()
            r = http.request('GET', self.jwks_uri)
            if r.status != 200:
                error_message = 'OpenID returned error code %s on jwks_uri: %s' % (r.status, self.jwks_uri)
                logger.critical(error_message)
                raise JWTClientException(error_message)
            jwk_set_json = r.data.decode('UTF-8')
        else:
            from django_jwt.server.models import Key
            jwk_set_json = json.dumps({'keys': Key.get_jwk_set()})
        self.jwks = JWKSet.from_json(jwk_set_json)

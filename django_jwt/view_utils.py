import hashlib
import json
import os.path

import base64
from datetime import datetime, timedelta

from Crypto.PublicKey import RSA
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from django_jwt.patterns import Singleton


class FakeJWT(metaclass=Singleton):
    def __init__(self) -> None:
        super().__init__()
        self.jks = self.get_jwk()

    def get_jwk(self):
        if not os.path.isdir('files'):
            os.mkdir('files')
        if not os.path.isfile('files/rsa.pem'):
            with open('files/rsa.pem', 'wb+') as file:
                private_key = RSA.generate(2048)
                private_key = private_key.export_key()
                file.write(private_key)
        else:
            with open('files/rsa.pem', 'rb') as file:
                private_key = file.read()
        jwk = JWK()
        jwk.import_from_pem(private_key, kid='0')
        return jwk

    def generate_jwt(self, claim):
        jwt = JWT(header={'kid': self.jks.key_id, 'alg': 'RS256', 'typ': 'JWT'}, claims=claim)
        jwt.make_signed_token(self.jks)
        return jwt.serialize()


def get_jwks():
    return {'keys': [FakeJWT().jks.export_public(as_dict=True)]}


def get_sub_jwt(token):
    jwt = JWT()
    jwt.deserialize(token, FakeJWT().jks)
    claims = json.loads(jwt.claims)
    return claims.get('sub')


def calculate_at_hash(access_token, hash_alg):
    """Helper method for calculating an access token
    hash, as described in http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
    Its value is the base64url encoding of the left-most half of the hash of the octets
    of the ASCII representation of the access_token value, where the hash algorithm
    used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE
    Header. For instance, if the alg is RS256, hash the access_token value with SHA-256,
    then take the left-most 128 bits and base64url encode them. The at_hash value is a
    case sensitive string.
    Args:
        access_token (str): An access token string.
        hash_alg (callable): A callable returning a hash object, e.g. hashlib.sha256
    """
    hash_digest = hash_alg(access_token.encode('ascii')).digest()
    cut_at = int(len(hash_digest) / 2)
    truncated = hash_digest[:cut_at]
    at_hash = base64url_encode(truncated)
    return at_hash.decode('ascii')


def base64url_encode(input):
    """Helper method to base64url_encode a string.
    Args:
        input (str): A base64url_encoded string to encode.
    """
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def crear_url_amb_jwt(request):
    fake_jwt = FakeJWT()
    now = datetime.now()
    expiration = timedelta(days=1)
    claim = {'sub': request.POST['username'], 'nonce': request.GET.get('nonce'), 'iat': int(now.timestamp()),
             'exp': int((now + expiration).timestamp()), 'iss': request.build_absolute_uri('/'),
             'aud': [request.GET.get('client_id')]}
    access_token = fake_jwt.generate_jwt(claim=claim)
    claim['at_hash'] = calculate_at_hash(access_token, hashlib.sha256)
    id_token = fake_jwt.generate_jwt(claim=claim)
    url = "%s#access_token=%s&id_token=%s&state=%s" % (request.GET.get('redirect_uri'), access_token,
                                                       str(id_token), request.GET.get('state'))
    return url

# -*- coding: utf-8 -*-

from hmac_authentication import exceptions

import base64
import collections
import enum
import hashlib
import hmac


ValidationResult = collections.namedtuple('ValidationResult',
    ['result_code', 'header_signature', 'computed_signature'])


class ValidationResultCodes(enum.Enum):
    '''Defines the result codes used in ValidationResult.'''

    # The incoming result did not have a signature header
    NO_SIGNATURE = 1

    # The signature header was not parseable
    INVALID_FORMAT = 2

    # The signature header specified an unsupported algorithm
    UNSUPPORTED_ALGORITHM = 3

    # The signature from the request header matched the locally-computed
    # signature
    MATCH = 4

    # The signature from the request header did not match the locally-computed
    # signature
    MISMATCH = 5


def header_name_to_wsgi(header_name):
    wsgi_name = header_name.upper().replace('-', '_')
    if wsgi_name not in ['CONTENT_TYPE', 'CONTENT_LENGTH']:
        wsgi_name = 'HTTP_' + wsgi_name
    return wsgi_name


def _compare_signatures(header, computed):
    if hmac.compare_digest(header.encode('utf8'), computed.encode('utf8')):
        return ValidationResultCodes.MATCH
    return ValidationResultCodes.MISMATCH


class HmacAuth(object):
    '''HmacAuth signs outbound requests and authenticates inbound requests.

    Note that the method parameters called "req" or "request" correspond to
    the WSGI "environ" interface define in PEP 333:
      https://www.python.org/dev/peps/pep-0333/
    '''

    def __init__(self, digest_name, secret_key, signature_header, headers):
        if not digest_name in hashlib.algorithms_available:
            raise exceptions.Error(
                'HMAC authentication digest is not supported: ' + digest_name)
        self._digest = getattr(hashlib, digest_name)
        self._secret_key = secret_key
        self._signature_header = header_name_to_wsgi(signature_header)
        self._headers = [header_name_to_wsgi(h) for h in headers]

    # NOTE(mbland): Best I can tell, either the WSGI layer or every sane HTTP
    # request tool will compile multiply-defined headers into a single header.
    # At any rate, multiply-defined headers are abad idea, and the WSGI
    # environ interface only appears to ever return a single string.
    def _signed_headers(self, environ):
        return [str(environ.get(h, '')) for h in self._headers]

    def string_to_sign(self, environ):
        '''Produces the string that will be prefixed to the request body and
        used to generate the signature.
        '''
        components = [environ['REQUEST_METHOD']]
        components.extend(self._signed_headers(environ))
        components.append(
            environ.get('PATH_INFO', '/') + environ.get('QUERY_STRING', ''))
        return '\n'.join(components) + '\n'

    # NOTE(mbland): I'm not sure the outbound WSGI HTTP request interface is
    # symmetrical to the inbound "environ" interface. Must go deeper.
    def sign_request(self, environ):
        '''Adds a signature header to the request.'''
        environ[self._signature_header] = self.request_signature(environ)

    def request_signature(self, environ):
        '''Generates a signature for the request.'''
        return self._request_signature(environ, self._digest)

    def _request_signature(self, environ, digest):
        h = hmac.new(self._secret_key.encode('utf8'),
            self.string_to_sign(environ).encode('utf8'),
            digest)
        body = environ.get('wsgi.input')
        if body is not None:
            h.update(body.getvalue().encode('utf8'))
        return digest().name + ' ' + base64.b64encode(h.digest()).decode('utf8')

    def signature_from_header(self, environ):
        '''Retrieves the signature included in the request header.'''
        return environ.get(self._signature_header)

    def validate_request(self, environ):
        '''Authenticates the request by comparing HMAC signatures.
        
        Returns the result code, the signature from the header, and the
        locally-computed signature as a ValidationResult.
        '''
        header = self.signature_from_header(environ)
        if header is None:
            return ValidationResult(ValidationResultCodes.NO_SIGNATURE,
                None, None)
        components = header.split(' ')

        if len(components) != 2:
            return ValidationResult(ValidationResultCodes.INVALID_FORMAT,
                header, None)

        digest_name = components[0]
        if not digest_name in hashlib.algorithms_available:
            return ValidationResult(ValidationResultCodes.UNSUPPORTED_ALGORITHM,
                header, None)

        computed = self._request_signature(
            environ, getattr(hashlib, digest_name))
        return ValidationResult(_compare_signatures(header, computed),
            header, computed)


class HmacMiddleware(object):
    '''WSGI middleware for authenticating incoming HTTP requests via HmacAuth'''
    
    def __init__(self, app, hmac_auth):
        self.app = app
        self.hmac_auth = hmac_auth

    def __call__(self, environ, start_response):
        result = self.auth(environ)
        if result.result_code != ValidationResults.MATCH:
            try:
                abort(401)
            except HTTPException as error:
                return error(environ, start_response)
        return self.app(environ, start_response)

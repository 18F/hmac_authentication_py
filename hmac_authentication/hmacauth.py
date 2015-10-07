# -*- coding: utf-8 -*-

from hmac_authentication import exceptions
import base64
import hashlib
import hmac

class HmacAuth(object):
    '''HmacAuth signs outbound requests and authenticates inbound requests.

    Note that the method parameters called "req" or "request" correspond to
    the WSGI "environ" interface define in PEP 333:
      https://www.python.org/dev/peps/pep-0333/
    '''

    NO_SIGNATURE = 1
    INVALID_FORMAT = 2
    UNSUPPORTED_ALGORITHM = 3
    MATCH = 4
    MISMATCH = 5

    RESULT_CODE_STRINGS = [
        'NO_SIGNATURE',
        'INVALID_FORMAT',
        'UNSUPPORTED_ALGORITHM',
        'MATCH',
        'MISMATCH',
    ]

    @staticmethod
    def result_code_to_string(code):
        '''Maps one of the constants representing validate_request() return
        codes to a string representation from RESULT_CODE_STRINGS.
        '''
        index = code - 1
        if index >= 0 and index < len(HmacAuth.RESULT_CODE_STRINGS):
            return HmacAuth.RESULT_CODE_STRINGS[index]

    @staticmethod
    def header_name_to_wsgi(header_name):
        wsgi_name = header_name.upper().replace('-', '_')
        if wsgi_name not in ['CONTENT_TYPE', 'CONTENT_LENGTH']:
            wsgi_name = 'HTTP_' + wsgi_name
        return wsgi_name

    def __init__(self, digest_name, secret_key, signature_header, headers):
        if not digest_name in hashlib.algorithms_available:
            raise exceptions.Error(
                'HMAC authentication digest is not supported: ' + digest_name)
        self._digest = getattr(hashlib, digest_name)
        self._digest_name = digest_name
        self._secret_key = secret_key
        self._signature_header = HmacAuth.header_name_to_wsgi(signature_header)
        self._headers = [HmacAuth.header_name_to_wsgi(h) for h in headers]

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
        return self._request_signature(
            environ, self._digest, self._digest_name)

    def _request_signature(self, environ, digest, digest_name):
        h = hmac.new(self._secret_key.encode('utf8'),
            self.string_to_sign(environ).encode('utf8'),
            digest)
        body = environ.get('wsgi.input')
        if body is not None:
            h.update(body.getvalue().encode('utf8'))
        return digest_name + ' ' + base64.b64encode(h.digest()).decode('utf8')

    def signature_from_header(self, environ):
        '''Retrieves the signature included in the request header.'''
        return environ.get(self._signature_header)

    @staticmethod
    def _compare_signatures(header, computed):
        if hmac.compare_digest(header.encode('utf8'), computed.encode('utf8')):
            return HmacAuth.MATCH
        else:
            return HmacAuth.MISMATCH

    def validate_request(self, environ):
        '''Authenticates the request, returning the result code, the signature
	from the header, and the locally-computed signature.
    
        Returns a tuple containing (the comparison result, the signature from
        the request header, and the locally-computed signature). The
        comparison result will be one of the following class constants:

        - NO_SIGNATURE: the incoming result did not have a signature header
        - INVALID_FORMAT: the signature header was not parseable
        - UNSUPPORTED_ALGORITHM: the signature header specified an unsupported
          algorithm
        - MATCH: the signature from the request header matched the
          locally-computed signature
        - MISMATCH: the signature from the request header did not match the
          locally-computed signature

        These values can be passed to result_code_to_string() to return the
        corresponding string value.
        '''
        header = self.signature_from_header(environ)
        if header is None:
            return HmacAuth.NO_SIGNATURE, None, None
        components = header.split(' ')

        if len(components) != 2:
            return HmacAuth.INVALID_FORMAT, header, None

        digest_name = components[0]
        if not digest_name in hashlib.algorithms_available:
            return HmacAuth.UNSUPPORTED_ALGORITHM, header, None

        computed = self._request_signature(
            environ, getattr(hashlib, digest_name), digest_name)
        return HmacAuth._compare_signatures(header, computed), header, computed

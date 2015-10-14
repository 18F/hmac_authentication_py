# -*- coding: utf-8 -*-

import hashlib

import six
import pytest

from hmac_authentication.hmacauth import HmacAuth, AuthenticationResultCodes


# These correspond to the headers used in bitly/oauth2_proxy#147.
HEADERS = [
    'Content-Length',
    'Content-Md5',
    'Content-Type',
    'Date',
    'Authorization',
    'X-Forwarded-User',
    'X-Forwarded-Email',
    'X-Forwarded-Access-Token',
    'Cookie',
    'Gap-Auth',
]


@pytest.fixture
def auth():
    return HmacAuth(hashlib.sha1, 'foobar', 'Gap-Signature', HEADERS)


class TestRequestSignature(object):
    def test_request_signature_post(self, auth):
        payload = '{ "hello": "world!" }'
        environ = {
            'REQUEST_METHOD': 'POST',
            'wsgi.url_scheme': 'http',
            'SERVER_NAME': 'localhost',
            'SERVER_PORT': '80',
            'PATH_INFO': '/foo/bar',
            'CONTENT_TYPE': 'application/json',
            'CONTENT_LENGTH': len(payload),
            'HTTP_CONTENT_MD5': 'deadbeef',
            'HTTP_DATE': '2015-09-28',
            'HTTP_AUTHORIZATION': 'trust me',
            'HTTP_X_FORWARDED_USER': 'mbland',
            'HTTP_X_FORWARDED_EMAIL': 'mbland@acm.org',
            'HTTP_X_FORWARDED_ACCESS_TOKEN': 'feedbead',
            'HTTP_COOKIE': 'foo; bar; baz=quux',
            'HTTP_GAP_AUTH': 'mbland',
            'wsgi.input': six.StringIO(payload),
        }
        expected = '\n'.join([
            'POST',
            str(len(payload)),
            'deadbeef',
            'application/json',
            '2015-09-28',
            'trust me',
            'mbland',
            'mbland@acm.org',
            'feedbead',
            'foo; bar; baz=quux',
            'mbland',
            '/foo/bar',
        ]) + '\n'
        assert expected == auth.string_to_sign(environ)
        assert ('sha1 K4IrVDtMCRwwW8Oms0VyZWMjXHI=' ==
            auth.request_signature(environ))

    def test_request_signature_get(self, auth):
        environ = {
            'REQUEST_METHOD': 'GET',
            'wsgi.url_scheme': 'http',
            'SERVER_NAME': 'localhost',
            'SERVER_PORT': '80',
            'PATH_INFO': '/foo/bar?baz=quux%2Fxyzzy#plugh',
            'HTTP_DATE': '2015-09-29',
            'HTTP_COOKIE': 'foo; bar; baz=quux',
            'HTTP_GAP_AUTH': 'mbland',
        }
        expected = '\n'.join([
            'GET',
            '',
            '',
            '',
            '2015-09-29',
            '',
            '',
            '',
            '',
            'foo; bar; baz=quux',
            'mbland',
            '/foo/bar?baz=quux%2Fxyzzy#plugh',
        ]) + '\n'
        assert expected == auth.string_to_sign(environ)
        assert ('sha1 ih5Jce9nsltry63rR4ImNz2hdnk=' ==
            auth.request_signature(environ))


@pytest.fixture
def environ():
    return {
        'REQUEST_METHOD': 'GET',
        'wsgi.url_scheme': 'http',
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '80',
        'PATH_INFO': '/foo/bar?baz=quux%2Fxyzzy#plugh',
    }


class TestAuthenticateRequest(object):
    def test_authenticate_request_no_signature(self, auth, environ):
        result, header, computed = auth.authenticate_request(environ)
        assert AuthenticationResultCodes.NO_SIGNATURE == result
        assert header is None
        assert computed is None

    def test_authenticate_request_invalid_format(self, auth, environ):
        bad_value = 'should be algorithm and digest value'
        environ['HTTP_GAP_SIGNATURE'] = bad_value
        result, header, computed = auth.authenticate_request(environ)
        assert AuthenticationResultCodes.INVALID_FORMAT == result
        assert bad_value == header
        assert computed is None

    def test_authenticate_request_unsupported_algorithm(self, auth, environ):
        valid_signature = auth.request_signature(environ)
        components = valid_signature.split(' ')
        signature_with_unsupported_algorithm = 'unsupported ' + components[1]
        environ['HTTP_GAP_SIGNATURE'] = signature_with_unsupported_algorithm
        result, header, computed = auth.authenticate_request(environ)
        assert AuthenticationResultCodes.UNSUPPORTED_ALGORITHM == result
        assert signature_with_unsupported_algorithm == header
        assert computed is None

    def test_authenticate_request_match(self, auth, environ):
        expected_signature = auth.request_signature(environ)
        auth.sign_request(environ)
        result, header, computed = auth.authenticate_request(environ)
        assert AuthenticationResultCodes.MATCH == result
        assert expected_signature == header
        assert expected_signature == computed

    def test_authenticate_request_mismatch(self, auth, environ):
        barbaz_auth = HmacAuth(hashlib.sha1, 'barbaz', 'Gap-Signature', HEADERS)
        auth.sign_request(environ)
        result, header, computed = barbaz_auth.authenticate_request(environ)
        assert AuthenticationResultCodes.MISMATCH == result
        assert auth.request_signature(environ) == header
        assert barbaz_auth.request_signature(environ) == computed

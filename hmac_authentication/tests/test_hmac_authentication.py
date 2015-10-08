#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hmac_authentication import hmacauth
from hmac_authentication import exceptions

import hashlib
import io
import unittest


HmacAuth = hmacauth.HmacAuth
ValidationResult = hmacauth.ValidationResult
ValidationResultCodes = hmacauth.ValidationResultCodes


class HmacAuthTest(unittest.TestCase):
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

    auth = HmacAuth(hashlib.sha1, 'foobar', 'Gap-Signature', HEADERS)


class RequestSignatureTest(HmacAuthTest):
    def test_request_signature_post(self):
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
            'wsgi.input': io.StringIO(payload),
        }
        self.assertEqual('\n'.join([
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
            ]) + '\n',
            self.auth.string_to_sign(environ))
        self.assertEqual('sha1 K4IrVDtMCRwwW8Oms0VyZWMjXHI=',
            self.auth.request_signature(environ))

    def test_request_signature_get(self):
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
        self.assertEqual('\n'.join([
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
            ]) + '\n',
            self.auth.string_to_sign(environ))
        self.assertEqual('sha1 ih5Jce9nsltry63rR4ImNz2hdnk=',
            self.auth.request_signature(environ))


class ValidateRequestTest(HmacAuthTest):
    def setUp(self):
        self.environ = {
            'REQUEST_METHOD': 'GET',
            'wsgi.url_scheme': 'http',
            'SERVER_NAME': 'localhost',
            'SERVER_PORT': '80',
            'PATH_INFO': '/foo/bar?baz=quux%2Fxyzzy#plugh',
        }

    def test_validate_request_no_signature(self):
        result, header, computed = self.auth.validate_request(self.environ)
        self.assertEqual(ValidationResultCodes.NO_SIGNATURE, result)
        self.assertIsNone(header)
        self.assertIsNone(computed)

    def test_validate_request_invalid_format(self):
        bad_value = 'should be algorithm and digest value'
        self.environ['HTTP_GAP_SIGNATURE'] = bad_value
        result, header, computed = self.auth.validate_request(self.environ)
        self.assertEqual(ValidationResultCodes.INVALID_FORMAT, result)
        self.assertEqual(bad_value, header)
        self.assertIsNone(computed)

    def test_validate_request_unsupported_algorithm(self):
        valid_signature = self.auth.request_signature(self.environ)
        components = valid_signature.split(' ')
        signature_with_unsupported_algorithm = 'unsupported ' + components[1]
        self.environ['HTTP_GAP_SIGNATURE'] = \
            signature_with_unsupported_algorithm
        result, header, computed = self.auth.validate_request(self.environ)
        self.assertEqual(ValidationResultCodes.UNSUPPORTED_ALGORITHM, result)
        self.assertEqual(signature_with_unsupported_algorithm, header)
        self.assertIsNone(computed)

    def test_validate_request_match(self):
        expected_signature = self.auth.request_signature(self.environ)
        self.auth.sign_request(self.environ)
        result, header, computed = self.auth.validate_request(self.environ)
        self.assertEqual(ValidationResultCodes.MATCH, result)
        self.assertEqual(expected_signature, header)
        self.assertEqual(expected_signature, computed)

    def test_validate_request_mismatch(self):
        barbaz_auth = HmacAuth(hashlib.sha1, 'barbaz', 'Gap-Signature',
            HmacAuthTest.HEADERS)
        self.auth.sign_request(self.environ)
        result, header, computed = barbaz_auth.validate_request(self.environ)
        self.assertEqual(ValidationResultCodes.MISMATCH, result)
        self.assertEqual(self.auth.request_signature(self.environ), header)
        self.assertEqual(barbaz_auth.request_signature(self.environ), computed)


if __name__ == '__main__':
    unittest.main()

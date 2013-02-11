#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for requests_kerberos."""

from mock import Mock, patch
import requests
import requests_kerberos
import unittest

# kerberos.authClientInit() is called with the service name (HTTP@FQDN) and
# returns 1 and a kerberos context object on success. Returns -1 on failure.
clientInitComplete = Mock(return_value=(1, "CTX"))
clientInitError = Mock(return_value=(-1, "CTX"))

# kerberos.authGSSClientStep() is called with the kerberos context object
# returned by authGSSClientInit and the negotiate auth token provided in the
# http response's www-authenticate header. It returns 0 or 1 on success. 0
# Indicates that authentication is progressing but not complete.
clientStepComplete = Mock(return_value=1)
clientStepContinue = Mock(return_value=0)
clientStepError = Mock(return_value=-1)

# kerberos.authGSSCLientResponse() is called with the kerberos context which
# was initially returned by authGSSClientInit and had been mutated by a call by
# authGSSClientStep. It returns a string.
clientResponse = Mock(return_value="GSSRESPONSE")

# Note: we're not using the @mock.patch decorator:
# > My only word of warning is that in the past, the patch decorator hides
# > tests when using the standard unittest library.
# > -- sigmavirus24 in https://github.com/requests/requests-kerberos/issues/1


class KerberosTestCase(unittest.TestCase):

    def setUp(self):
        """Setup."""
        pass

    def tearDown(self):
        """Teardown."""
        pass

    def test_negotate_value_extraction(self):
        response = requests.Response()
        response.headers = {'www-authenticate': 'negotiate token'}
        self.assertEqual(
            requests_kerberos.kerberos_._negotiate_value(response),
            'token'
        )

    def test_negotate_value_extraction_none(self):
        response = requests.Response()
        response.headers = {}
        self.assertIs(
            requests_kerberos.kerberos_._negotiate_value(response),
            None
        )

    def test_generate_request_header(self):
        with patch.multiple('kerberos',
                            authGSSClientInit=clientInitComplete,
                            authGSSClientResponse=clientResponse,
                            authGSSClientStep=clientStepContinue):
            response = requests.Response()
            response.url = "http://www.example.org/"
            response.headers = {'www-authenticate': 'negotiate token'}
            auth = requests_kerberos.HTTPKerberosAuth()
            self.assertEqual(
                auth.generate_request_header(response),
                "Negotiate GSSRESPONSE"
            )
            clientInitComplete.assert_called_with("HTTP@www.example.org")
            clientStepContinue.assert_called_with("CTX", "token")
            clientResponse.assert_called_with("CTX")

    def test_generate_request_header_init_error(self):
        with patch.multiple('kerberos',
                            authGSSClientInit=clientInitError,
                            authGSSClientResponse=clientResponse,
                            authGSSClientStep=clientStepContinue):
            response = requests.Response()
            response.url = "http://www.example.org/"
            response.headers = {'www-authenticate': 'negotiate token'}
            auth = requests_kerberos.HTTPKerberosAuth()
            self.assertRaises(Exception,
                              auth.generate_request_header,
                              response)
            clientInitError.assert_called_with("HTTP@www.example.org")
            clientStepContinue.assert_not_called()
            clientResponse.assert_not_called()

    def test_generate_request_header_step_error(self):
        with patch.multiple('kerberos',
                            authGSSClientInit=clientInitComplete,
                            authGSSClientResponse=clientResponse,
                            authGSSClientStep=clientStepError):
            response = requests.Response()
            response.url = "http://www.example.org/"
            response.headers = {'www-authenticate': 'negotiate token'}
            auth = requests_kerberos.HTTPKerberosAuth()
            self.assertRaises(Exception,
                              auth.generate_request_header,
                              response)
            clientInitComplete.assert_called_with("HTTP@www.example.org")
            clientStepError.assert_called_with("CTX", "token")
            clientResponse.assert_not_called()

if __name__ == '__main__':
    unittest.main()

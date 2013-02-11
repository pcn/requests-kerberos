#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for requests_kerberos."""

import unittest
import mock
import requests_kerberos
import requests

# kerberos.authClientInit() is called with the service name (HTTP@FQDN) and
# returns 1 and a kerberos context object on success. Returns -1 on failure.
clientInitComplete = mock.Mock(return_value=(1, "CTX"))
clientInitError = mock.Mock(return_value=(-1, "CTX"))

# kerberos.authGSSClientStep() is called with the kerberos context object
# returned by authGSSClientInit and the negotiate auth token provided in the
# http response's www-authenticate header. It returns 0 or 1 on success. 0
# Indicates that authentication is progressing but not complete.
clientStepComplete = mock.Mock(return_value=1)
clientStepContinue = mock.Mock(return_value=0)
clientStepError = mock.Mock(return_value=-1)

# kerberos.authGSSCLientResponse() is called with the kerberos context which
# was initially returned by authGSSClientInit and had been mutated by a call by
# authGSSClientStep. It returns a string.
clientResponse = mock.Mock(return_value="GSSRESPONSE")


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

    @mock.patch('kerberos.authGSSClientResponse', clientResponse)
    @mock.patch('kerberos.authGSSClientStep', clientStepContinue)
    @mock.patch('kerberos.authGSSClientInit', clientInitComplete)
    def test_generate_request_header(self):
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

    @mock.patch('kerberos.authGSSClientResponse', clientResponse)
    @mock.patch('kerberos.authGSSClientStep', clientStepContinue)
    @mock.patch('kerberos.authGSSClientInit', clientInitError)
    def test_generate_request_header_init_error(self):
        response = requests.Response()
        response.url = "http://www.example.org/"
        response.headers = {'www-authenticate': 'negotiate token'}
        auth = requests_kerberos.HTTPKerberosAuth()
        self.assertRaises(Exception, auth.generate_request_header, response)
        clientInitError.assert_called_with("HTTP@www.example.org")
        clientStepContinue.assert_not_called()
        clientResponse.assert_not_called()

    @mock.patch('kerberos.authGSSClientResponse', clientResponse)
    @mock.patch('kerberos.authGSSClientStep', clientStepError)
    @mock.patch('kerberos.authGSSClientInit', clientInitComplete)
    def test_generate_request_header_step_error(self):
        response = requests.Response()
        response.url = "http://www.example.org/"
        response.headers = {'www-authenticate': 'negotiate token'}
        auth = requests_kerberos.HTTPKerberosAuth()
        self.assertRaises(Exception, auth.generate_request_header, response)
        clientInitComplete.assert_called_with("HTTP@www.example.org")
        clientStepError.assert_called_with("CTX", "token")
        clientResponse.assert_not_called()


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for requests_kerberos."""

import unittest
import mock
import requests_kerberos
import requests

# kerberos.authClientInit() is called with the service name (HTTP@FQDN) and
# returns 1 and a kerberos context object on success.
clientinit = mock.Mock(return_value=(1, "CTX"))

# kerberos.authGSSClientStep() is called with the kerberos context object
# returned by authGSSClientInit and the negotiate auth token provided in the
# http response's www-authenticate header. It returns 1 on success.
clientstep = mock.Mock(return_value=1)

# kerberos.authGSSCLientResponse() is called with the kerberos context which
# was initially returned by authGSSClientInit and had been mutated by a call by
# authGSSClientStep. It returns a string on success.
clientresponse = mock.Mock(return_value="GSSRESPONSE")


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

    @mock.patch('kerberos.authGSSClientResponse', clientresponse)
    @mock.patch('kerberos.authGSSClientStep', clientstep)
    @mock.patch('kerberos.authGSSClientInit', clientinit)
    def test_generate_request_header(self):
        response = requests.Response()
        response.status_code = 401
        response.url = "http://www.example.org/"
        response.headers = {'www-authenticate': 'negotiate token'}
        auth = requests_kerberos.HTTPKerberosAuth()
        self.assertEqual(
            auth.generate_request_header(response),
            "Negotiate GSSRESPONSE"
        )
        clientinit.assert_called_with("HTTP@www.example.org")
        clientstep.assert_called_with("CTX", "token")
        clientresponse.assert_called_with("CTX")


if __name__ == '__main__':
    unittest.main()

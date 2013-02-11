"""
requests Kerberos/GSSAPI authentication library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Requests is an HTTP library, written in Python, for human beings. This library
adds optional Kerberos/GSSAPI authentication support and supports mutual
authentication. Basic GET usage:

    >>> import requests
    >>> from requests_kerberos import HTTPKerberosAuth
    >>> r = requests.get("http://example.org", auth=HTTPKerberosAuth())

... or without mutual authentication:

    >>> r = requests.get("http://example.org", auth=HTTPKerberosAuth(require_mutual_auth=False))


The entire `requests.api` should be supported.
"""
from .kerberos_ import HTTPKerberosAuth, MutualAuthenticationError


__all__ = [HTTPKerberosAuth, MutualAuthenticationError]
__version__ = '0.1'

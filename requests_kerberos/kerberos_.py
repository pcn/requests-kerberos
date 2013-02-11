from requests.auth import AuthBase
from requests.compat import urlparse
from requests.exceptions import RequestException
import kerberos
import re
import logging

log = logging.getLogger(__name__)


# NOTES:
# If authentication fails, the server response will be passed to the user. This
# is likely to be a 401. A 403 would indicate successful authentication with an
# unauthorized user.
# If the client requires mutual authentication (the default, similar to ssl
# certificate validation in requests proper), an exception will be raised so
# that the user does not have the opportunity to accept an untrusted response.
# If they're okay without requiring mutual authentication, then they can
# specify that when constructing their HTTPKerberosAuth object.


class MutualAuthenticationError(RequestException):
    """Mutual Authentication Error"""


def _negotiate_value(response):
    """Extracts the gssapi authentication token from the appropriate header"""
    if hasattr(_negotiate_value, 'regex'):
        regex = _negotiate_value.regex
    else:
        # There's no need to re-compile this EVERY time it is called. Compile
        # it once and you won't have the performance hit of the compilation.
        regex = re.compile('(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)
        _negotiate_value.regex = regex

    authreq = response.headers.get('www-authenticate', None)

    if authreq:
        match_obj = regex.search(authreq)
        if match_obj:
            return match_obj.group(1)

    return None


class HTTPKerberosAuth(AuthBase):
    """Attaches HTTP GSSAPI/Kerberos Authentication to the given Request
    object."""
    def __init__(self, require_mutual_auth=True):
        self.context = None
        self.require_mutual_auth = require_mutual_auth

    def generate_request_header(self, response):
        """
        Generates the GSSAPI authentication token with kerberos.

        If any GSSAPI step fails, return None.

        """
        host = urlparse(response.url).netloc
        tail, _, head = host.rpartition(':')
        domain = tail if tail else head

        try:
            result, self.context = kerberos.authGSSClientInit("HTTP@{0}".format(
                domain))
        except kerberos.GSSError as e:
            log.error("generate_request_header(): authGSSClientInit() failed:")
            log.exception(e)
            return None

        if result < 1:
            log.error("generate_request_header(): authGSSClientInit() failed: "
                      "{0}".format(result))
            return None

        try:
            result = kerberos.authGSSClientStep(self.context,
                                                _negotiate_value(response))
        except kerberos.GSSError as e:
            log.error("generate_request_header(): authGSSClientStep() failed:")
            log.exception(e)
            return None

        if result < 0:
            log.error("generate_request_header(): authGSSClientStep() failed: "
                      "{0}".format(result))
            return None

        gss_response = kerberos.authGSSClientResponse(self.context)

        return "Negotiate {0}".format(gss_response)

    def authenticate_user(self, response):
        """Handles user authentication with gssapi/kerberos"""

        auth_header = self.generate_request_header(response)
        if auth_header is None:
            # GSS Failure, return existing response
            return response

        log.debug("authenticate_user(): Authorization header: {0}".format(
            auth_header))
        response.request.headers['Authorization'] = auth_header

        # Consume the content so we can reuse the connection for the next request.
        response.content
        response.raw.release_conn()

        _r = response.connection.send(response.request)
        _r.history.append(response)

        log.debug("authenticate_user(): returning {0}".format(_r))
        return _r

    def handle_401(self, response):
        """Handles 401's, attempts to use gssapi/kerberos authentication"""

        log.debug("handle_401(): Handling: 401")
        if _negotiate_value(response) is not None:
            _r = self.authenticate_user(response)
            log.debug("handle_401(): returning {0}".format(_r))
            return _r
        else:
            log.debug("handle_401(): Kerberos is not supported")
            log.debug("handle_401(): returning {0}".format(response))
            return response

    def handle_other(self, response):
        """Handles all responses with the exception of 401s.

        This is necessary so that we can authenticate responses if requested"""

        log.debug("handle_other(): Handling: %d" % response.status_code)
        self.deregister(response)
        if self.require_mutual_auth:
            if _negotiate_value(response) is not None:
                log.debug("handle_other(): Authenticating the server")
                _r = self.authenticate_server(response)
                if _r is None:
                    # Mutual authentication failure when mutual auth is
                    # required, raise an exception so the user doesnt use an
                    # untrusted response.
                    log.error("handle_other(): Mutual authentication failed")
                    raise MutualAuthenticationError("Unable to authenticate server")
                log.debug("handle_other(): returning {0}".format(_r))
                return _r
            else:
                # Unable to attempt mutual authentication when mutual auth is
                # required, raise an exception so the user doesnt use an
                # untrusted response.
                log.error("handle_other(): Mutual authentication failed")
                raise MutualAuthenticationError("Unable to authenticate server")
        else:
            log.debug("handle_other(): returning {0}".format(response))
            return response

    def authenticate_server(self, response):
        """
        Uses GSSAPI to authenticate the server.

        Returns None on any GSSAPI failure.
        """

        log.debug("authenticate_server(): Authenticate header: {0}".format(
                _negotiate_value(response)))  # nopep8
        result = kerberos.authGSSClientStep(self.context,
                                            _negotiate_value(response))
        if result < 1:
            log.error("auhenticate_server(): authGSSClientStep() failed: "
                      "{0}".format(result))
            return None

        log.debug("authenticate_server(): returning {0}".format(response))
        return response

    def handle_response(self, response):
        """Takes the given response and tries kerberos-auth, as needed."""

        if response.status_code == 401:
            _r = self.handle_401(response)
            log.debug("handle_response(): returning {0}".format(_r))
            return _r
        else:
            _r = self.handle_other(response)
            log.debug("handle_response(): returning {0}".format(_r))
            return _r

        log.debug("handle_response(): returning {0}".format(response))
        return response

    def deregister(self, response):
        """Deregisters the response handler"""
        response.request.deregister_hook('response', self.handle_response)

    def __call__(self, response):
        response.register_hook('response', self.handle_response)
        return response

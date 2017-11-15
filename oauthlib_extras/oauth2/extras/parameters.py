"""
oauthlib_extras.oauth2.parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains methods related to `Section 4`_ of the OAuth 2 RFC.

.. _`Section 4`: http://tools.ietf.org/html/rfc6749#section-4
"""
from __future__ import absolute_import, unicode_literals

from oauthlib.oauth2.rfc6749.errors import MismatchingStateError
from .errors import MalformedResponseSecretError

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


# delimiter used for splitting the response secret
DELIMITER = '&'

def parse_authorization_code_response(secret, state=None):
    """Parse authorization grant response secret into a dict.

    If the resource owner grants the access request, the authorization
    server issues an authorization code and delivers it to the client in
    form of a secret, together wit
    format:

    **secret**
            REQUIRED.  The authorization code generated by the
            authorization server.  The authorization code MUST expire
            shortly after it is issued to mitigate the risk of leaks.  A
            maximum authorization code lifetime of 10 minutes is
            RECOMMENDED.  The client MUST NOT use the authorization code
            more than once.  If an authorization code is used more than
            once, the authorization server MUST deny the request and SHOULD
            revoke (when possible) all tokens previously issued based on
            that authorization code.  The authorization code is bound to
            the client identifier and redirection URI.

    **state**
            REQUIRED if the "state" parameter was present in the client
            authorization request.  The exact value received from the
            client.

    :param secret: The secret containing the oauth code and state.
    :param state: The state parameter from the authorization request.
    """
    params = {}
    secret_splitted = secret.split(DELIMITER)

    if len(secret_splitted) != 2 and len(secret_splitted) != 1:
        raise MalformedResponseSecretError()

    params['code'] = secret_splitted[0]
    if len(secret_splitted) > 1:
        # means we have a second element (state in this case)
        params['state'] = secret_splitted[1]

    if state and params.get('state', None) != state:
        raise MismatchingStateError()

    return params

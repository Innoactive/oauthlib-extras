from __future__ import absolute_import, unicode_literals

from oauthlib.oauth2.rfc6749.errors import MismatchingStateError
from .errors import MalformedResponseCodeError

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


# delimiter used for splitting the response secret
DELIMITER = '&'

def parse_authorization_code_response(code, state=None):
    params = {}
    code_splitted = code.split(DELIMITER)

    if len(code_splitted) != 2 and len(code_splitted) != 1:
        raise MalformedResponseCodeError()

    params['code'] = code_splitted[0]
    if len(code_splitted) > 1:
        # means we have a second element (state in this case)
        params['state'] = code_splitted[1]

    if state and params.get('state', None) != state:
        raise MismatchingStateError()

    return params

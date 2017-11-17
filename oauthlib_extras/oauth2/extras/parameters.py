from __future__ import absolute_import, unicode_literals

from oauthlib.oauth2.rfc6749.errors import MismatchingStateError
from .errors import MalformedResponsePushCodeError

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


# delimiter used for splitting the auth push code
DELIMITER = '&'

def parse_authorization_code_response(code, state=None):
    """
    Parses the auth push code, which consists of
    the auth code and optionally the state.
    :param code:
    :param state:
    :return:
    """
    params = {}
    code_splitted = code.split(DELIMITER)

    if len(code_splitted) != 2 and len(code_splitted) != 1:
        raise MalformedResponsePushCodeError()

    params['code'] = code_splitted[0]
    if len(code_splitted) > 1:
        # means we have a second element (state in this case)
        params['state'] = code_splitted[1]

    if state and params.get('state', None) != state:
        raise MismatchingStateError()

    return params

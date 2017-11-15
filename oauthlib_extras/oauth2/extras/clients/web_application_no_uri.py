from __future__ import absolute_import, unicode_literals

from ..parameters import parse_authorization_code_response

from oauthlib.oauth2 import Client
from oauthlib.oauth2.rfc6749.parameters import prepare_grant_uri, prepare_token_request


class WebApplicationClientNoUri(Client):
    """
    Same documentation applies as for original WebApplicationClient,
    except for the redirect_uri, which was left out here because
    the receiving end handles how code gets pushed to the user.
    """
    def __init__(self, client_id, code=None, **kwargs):
        super(WebApplicationClientNoUri, self).__init__(client_id, **kwargs)
        self.code = code

    def prepare_request_uri(self, uri, scope=None, state=None, **kwargs):
        return prepare_grant_uri(uri, self.client_id, 'code', scope=scope, state=state, **kwargs)

    def prepare_request_body(self, client_id=None, code=None, body='', redirect_uri=None, **kwargs):
        code = code or self.code
        return prepare_token_request('authorization_code_push', code=code, body=body, client_id=self.client_id,
                                     **kwargs)

    def parse_request_uri_response(self, code, state=None):
        response = parse_authorization_code_response(code, state=state)
        self._populate_attributes(response)
        return response

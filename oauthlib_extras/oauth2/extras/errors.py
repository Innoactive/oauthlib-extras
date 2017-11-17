from oauthlib.oauth2.rfc6749.errors import OAuth2Error


class MalformedResponsePushCodeError(OAuth2Error):
    """
    Error for the case of a malformed
    auth push code.
    """
    error = 'malformed_response_push_code'

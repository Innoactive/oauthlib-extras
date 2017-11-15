from oauthlib.oauth2.rfc6749.errors import OAuth2Error


class MalformedResponseCodeError(OAuth2Error):
    error = 'malformed_response_code'

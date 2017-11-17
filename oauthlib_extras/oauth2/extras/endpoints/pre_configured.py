from oauthlib.oauth2 import Server as ServerBase

class Server(ServerBase):
    auth_code_push_grant_class = None

    def __init__(self, request_validator, token_expires_in=None,
                 token_generator=None, refresh_token_generator=None,
                 *args, **kwargs):
        super(Server, self).__init__(request_validator, token_expires_in, token_generator,
                                             refresh_token_generator, *args, **kwargs)
        auth_push_grant = self.get_auth_code_push_grant_class()(request_validator)
        self._response_types['push_code'] = auth_push_grant
        self._grant_types['authorization_code_push'] = auth_push_grant

    def get_auth_code_push_grant_class(self):
        assert self.auth_code_push_grant_class is not None, (
            "'%s' should either include a `auth_code_push_grant_class` attribute, "
            "or override the `get_auth_code_push_grant_class()` method."
            % self.__class__.__name__
        )

        return self.auth_code_push_grant_class
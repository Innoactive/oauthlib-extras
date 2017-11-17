from oauthlib.oauth2 import Server as ServerBase


class Server(ServerBase):
    """
    Same as the original Server class, except for the auth_code_push_grant_class
    attribute, which creates an instance and adds the grant to the server.
    """
    # concrete implementation of the AuthorizationCodePushGrant
    auth_code_push_grant_class = None

    def __init__(self, request_validator, token_expires_in=None,
                 token_generator=None, refresh_token_generator=None,
                 *args, **kwargs):
        """
        Adds our AuthorizationCodePushGrant implementation to the server.
        :param request_validator:
        :param token_expires_in:
        :param token_generator:
        :param refresh_token_generator:
        :param args:
        :param kwargs:
        """
        super(Server, self).__init__(request_validator, token_expires_in, token_generator,
                                             refresh_token_generator, *args, **kwargs)
        auth_push_grant = self.get_auth_code_push_grant_class()(request_validator)
        self._response_types['push_code'] = auth_push_grant
        self._grant_types['authorization_code_push'] = auth_push_grant

    def get_auth_code_push_grant_class(self):
        """
        Returns concrete AuthorizationCodePushGrant class implementation.
        :return:
        """
        assert self.auth_code_push_grant_class is not None, (
            "'%s' should either include a `auth_code_push_grant_class` attribute, "
            "or override the `get_auth_code_push_grant_class()` method."
            % self.__class__.__name__
        )

        return self.auth_code_push_grant_class
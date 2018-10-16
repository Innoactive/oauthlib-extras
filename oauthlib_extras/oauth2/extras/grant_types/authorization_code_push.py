import logging

from oauthlib.oauth2 import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749 import errors

log = logging.getLogger(__name__)


class AuthorizationCodePushGrant(AuthorizationCodeGrant):
    """
    Very similar to AuthorizationCodeGrant.
    Redirect_uri was let out, and authorization_push method was added.
    You need to override this method in a concrete implementation to
    define the push (=transport) of the auth code.

    Success_uri amd error_uri should be self-explanatory.
    """
    success_uri = None
    error_uri = None
    response_types = ['push_code']

    def get_response_for_uri(self, uri):
        """
        Helper method, which constructs response
        :param uri:
        :return:
        """
        return ({'Location': uri}, None, 302)

    def create_authorization_response(self, request, token_handler):
        """
        Same as original method (of AuthorizationCodeGrant) except for the noted difference.
        :param request:
        :param token_handler:
        :return:
        """
        try:
            if not request.scopes:
                raise ValueError('Scopes must be set on post auth.')

            self.validate_authorization_request(request)
            log.debug('Pre resource owner authorization validation ok for %r.',
                      request)

        except errors.FatalClientError as e:
            log.debug('Fatal client error during validation of %r. %r.',
                      request, e)
            raise

        except errors.OAuth2Error as e:
            log.debug('Client error during validation of %r. %r.', request, e)
            return self.get_response_for_uri(self.get_error_uri(e))

        grant = self.create_authorization_code(request)
        log.debug('Saving grant %r for %r.', grant, request)
        self.request_validator.save_authorization_code(
            request.client_id, grant, request)
        # only difference to the original AuthorizationCodeGrant
        code = grant['code']
        state = grant.get('state', None)
        push_code = '{0}&{1}'.format(code, state) if state else code
        self.authorization_push(request, push_code)
        return self.get_response_for_uri(self.get_success_uri())

    def validate_authorization_request(self, request):
        """
        Same as original method (of AuthorizationCodeGrant) except for
        letting out the request_uri and request_uri validations
        :param request:
        :return:
        """
        for param in ('client_id', 'response_type', 'scope', 'state'):
            try:
                duplicate_params = request.duplicate_params
            except ValueError:
                raise errors.InvalidRequestFatalError(description='Unable to parse query string', request=request)
            if param in duplicate_params:
                raise errors.InvalidRequestFatalError(description='Duplicate %s parameter.' % param, request=request)

        if not request.client_id:
            raise errors.MissingClientIdError(request=request)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise errors.InvalidClientIdError(request=request)

        if request.response_type is None:
            raise errors.MissingResponseTypeError(request=request)
        elif request.response_type not in self.response_types:
            raise errors.UnsupportedResponseTypeError(request=request)

        if not self.request_validator.validate_response_type(request.client_id,
                                                             request.response_type,
                                                             request.client, request):

            log.debug('Client %s is not authorized to use response_type %s.',
                      request.client_id, request.response_type)
            raise errors.UnauthorizedClientError(request=request)

        self.validate_scopes(request)

        return request.scopes, {
            'client_id': request.client_id,
            'response_type': request.response_type,
            'state': request.state,
            'request': request,
            'redirect_uri': ''
        }

    def validate_token_request(self, request):
        """
        Same as original method (of AuthorizationCodeGrant) except for
        letting out the request_uri and request_uri validations
        :param request:
        :return:
        """
        if request.grant_type != 'authorization_code_push':
            raise errors.UnsupportedGrantTypeError(request=request)

        if request.code is None:
            raise errors.InvalidRequestError(
                description='Missing code parameter.', request=request)

        for param in ('client_id', 'grant_type'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description='Duplicate %s parameter.' % param,
                                                 request=request)

        if self.request_validator.client_authentication_required(request):
            if not self.request_validator.authenticate_client(request):
                log.debug('Client authentication failed, %r.', request)
                raise errors.InvalidClientError(request=request)
        elif not self.request_validator.authenticate_client_id(request.client_id, request):
            log.debug('Client authentication failed, %r.', request)
            raise errors.InvalidClientError(request=request)

        if not hasattr(request.client, 'client_id'):
            raise NotImplementedError('Authenticate client must set the '
                                      'request.client.client_id attribute '
                                      'in authenticate_client.')

        self.validate_grant_type(request)

        if not self.request_validator.validate_code(request.client_id,
                                                    request.code, request.client, request):
            log.debug('Client, %r (%r), is not allowed access to scopes %r.',
                      request.client_id, request.client, request.scopes)
            raise errors.InvalidGrantError(request=request)

        for attr in ('user', 'scopes'):
            if getattr(request, attr, None) is None:
                log.debug('request.%s was not set on code validation.', attr)

    def authorization_push(self, request, push_code):
        """
        Override it in a concrete implementation, to define the transport way.
        :param request: request object (contains user data etc)
        :param push_code: auth code as string
        :return:
        """
        raise NotImplementedError('The push transport needs to be implemented in a concrete implementation of this '
                                  'class.')

    def get_success_uri(self):
        """
        Returns success uri
        :return:
        """
        assert self.success_uri is not None, (
            "'%s' should either include a `success_uri` attribute, "
            "or override the `get_success_uri()` method."
            % self.__class__.__name__
        )

        return self.success_uri

    def get_error_uri(self, exception):
        """
        Returns error uri
        :param exception:
        :return:
        """
        assert self.error_uri is not None, (
            "'%s' should either include a `error_uri` attribute, "
            "or override the `get_error_uri()` method."
            % self.__class__.__name__
        )

        return self.error_uri
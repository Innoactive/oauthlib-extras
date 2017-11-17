import logging
from oauthlib.oauth2 import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749 import errors

log = logging.getLogger(__name__)


class AuthorizationCodePushGrant(AuthorizationCodeGrant):
    completion_response = None
    response_types = ['push_code']

    def create_authorization_response(self, request, token_handler):
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

        grant = self.create_authorization_code(request)
        for modifier in self._code_modifiers:
            grant = modifier(grant, token_handler, request)
        log.debug('Saving grant %r for %r.', grant, request)
        self.request_validator.save_authorization_code(
            request.client_id, grant, request)
        # only difference to the original AuthorizationCodeGrant
        code = grant['code']
        state = grant['state']
        push_code = '{0}&{1}'.format(code, state)
        self.authorization_push(request, push_code)
        return self.get_completion_response()

    def validate_authorization_request(self, request):
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

        request_info = {}
        for validator in self.custom_validators.pre_auth:
            request_info.update(validator(request))

        if request.response_type is None:
            raise errors.MissingResponseTypeError(request=request)
        elif not 'push_code' in request.response_type and request.response_type != 'none':
            raise errors.UnsupportedResponseTypeError(request=request)

        if not self.request_validator.validate_response_type(request.client_id,
                                                             request.response_type,
                                                             request.client, request):
            log.debug('Client %s is not authorized to use response_type %s.',
                      request.client_id, request.response_type)
            raise errors.UnauthorizedClientError(request=request)

        self.validate_scopes(request)

        request_info.update({
            'client_id': request.client_id,
            'response_type': request.response_type,
            'state': request.state,
            'request': request
        })

        for validator in self.custom_validators.post_auth:
            request_info.update(validator(request))

        return request.scopes, request_info

    def validate_token_request(self, request):
        if request.grant_type not in ['authorization_code_push']:
            raise errors.UnsupportedGrantTypeError(request=request)

        for validator in self.custom_validators.pre_token:
            validator(request)

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

        request.client_id = request.client_id or request.client.client_id

        self.validate_grant_type(request)

        if not self.request_validator.validate_code(request.client_id,
                                                    request.code, request.client, request):
            log.debug('Client, %r (%r), is not allowed access to scopes %r.',
                      request.client_id, request.client, request.scopes)
            raise errors.InvalidGrantError(request=request)

        for attr in ('user', 'scopes'):
            if getattr(request, attr, None) is None:
                log.debug('request.%s was not set on code validation.', attr)

        for validator in self.custom_validators.post_token:
            validator(request)

    def authorization_push(self, request, push_code):
        raise NotImplementedError('The push transport needs to be implemented in a concrete implementation of this '
                                  'class.')

    def get_completion_response(self):
        assert self.completion_response is not None, (
            "'%s' should either include a `completion_response` attribute, "
            "or override the `get_completion_response()` method."
            % self.__class__.__name__
        )

        return self.completion_response
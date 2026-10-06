from jakarta.inject import Singleton
from java.util import UUID
from micronaut.context.annotation import Requires
from micronaut.http import HttpRequest
from micronaut.security.authentication import AuthenticationFailureReason, AuthenticationRequest, AuthenticationResponse
from micronaut.security.authentication.provider import HttpRequestExecutorAuthenticationProvider
from micronaut.security.password import PasswordEncoder

from .UserStore import UserStore


@Requires(property="spec.name", value="PasswordEncodingTest")
# tag::clazz[]
@Singleton
class PasswordAuthenticationProvider(HttpRequestExecutorAuthenticationProvider):

    def __init__(self, userStore: UserStore, passwordEncoder: PasswordEncoder):
        self.userStore = userStore
        self.passwordEncoder = passwordEncoder
        self.unknownUserPassword = passwordEncoder.encode(UUID.randomUUID().toString())  # <1>

    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> AuthenticationResponse:
        encodedPassword = self.userStore.find_encoded_password(authRequest.getIdentity())
        matches = self.passwordEncoder.matches(authRequest.getSecret(), encodedPassword or self.unknownUserPassword)  # <2>
        if encodedPassword is not None and matches:
            return AuthenticationResponse.success(authRequest.getIdentity())
        return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)  # <3>
# end::clazz[]

from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.http import HttpRequest
from micronaut.security.authentication import AuthenticationFailureReason, AuthenticationRequest, AuthenticationResponse
from micronaut.security.authentication.provider import HttpRequestAuthenticationProvider
from micronaut.security.password import PasswordEncoder

from .UserStore import UserStore


@Requires(property="spec.name", value="PasswordEncodingTest")
# tag::clazz[]
@Singleton
class PasswordAuthenticationProvider(HttpRequestAuthenticationProvider):

    def __init__(self, userStore: UserStore, passwordEncoder: PasswordEncoder):
        self.userStore = userStore
        self.passwordEncoder = passwordEncoder

    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> AuthenticationResponse:
        encodedPassword = self.userStore.find_encoded_password(authRequest.getIdentity())
        if encodedPassword is not None and self.passwordEncoder.matches(authRequest.getSecret(), encodedPassword):  # <1>
            return AuthenticationResponse.success(authRequest.getIdentity())
        return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
# end::clazz[]

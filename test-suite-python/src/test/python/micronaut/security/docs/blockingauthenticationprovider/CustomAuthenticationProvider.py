from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.http import HttpRequest
from micronaut.security.authentication import AuthenticationFailureReason, AuthenticationRequest, AuthenticationResponse
from micronaut.security.authentication.provider import HttpRequestAuthenticationProvider


@Requires(property="spec.name", value="AuthenticationProviderTest")
# tag::clazz[]
@Singleton
class CustomAuthenticationProvider(HttpRequestAuthenticationProvider):

    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> AuthenticationResponse:
        if authRequest.getIdentity() == "user" and authRequest.getSecret() == "password":
            return AuthenticationResponse.success("user")
        return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
# end::clazz[]

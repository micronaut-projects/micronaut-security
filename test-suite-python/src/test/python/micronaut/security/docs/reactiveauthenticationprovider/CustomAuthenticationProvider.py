from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.core.async_.annotation import SingleResult
from micronaut.http import HttpRequest
from micronaut.security.authentication import AuthenticationFailureReason, AuthenticationRequest, AuthenticationResponse
from micronaut.security.authentication.provider import HttpRequestReactiveAuthenticationProvider
from org.reactivestreams import Publisher
from reactor.core.publisher import Mono


@Requires(property="spec.name", value="ReactiveAuthenticationProviderTest")
# tag::clazz[]
@Singleton
class CustomAuthenticationProvider(HttpRequestReactiveAuthenticationProvider):

    @SingleResult
    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> Publisher[AuthenticationResponse]:
        if authRequest.getIdentity() == "user" and authRequest.getSecret() == "password":
            rsp = AuthenticationResponse.success("user")
        else:
            rsp = AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
        return Mono.create(lambda emitter: emitter.success(rsp))
# end::clazz[]

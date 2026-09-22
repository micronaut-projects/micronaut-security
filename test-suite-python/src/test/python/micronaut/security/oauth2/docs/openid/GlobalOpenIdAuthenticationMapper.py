# tag::clazz[]
from jakarta.inject import Singleton
from micronaut.context.annotation import Replaces, Requires
from micronaut.security.authentication import AuthenticationResponse
from micronaut.security.oauth2.endpoint.authorization.state import State
from micronaut.security.oauth2.endpoint.token.response import DefaultOpenIdAuthenticationMapper, OpenIdAuthenticationMapper, OpenIdClaims, OpenIdTokenResponse
from org.reactivestreams import Publisher
from reactor.core.publisher import Flux


@Singleton
@Replaces(DefaultOpenIdAuthenticationMapper)
# end::clazz[]
@Requires(property="docs.classes")
# tag::clazz[]
class GlobalOpenIdAuthenticationMapper(OpenIdAuthenticationMapper):

    def createAuthenticationResponse(self, providerName: str, tokenResponse: OpenIdTokenResponse, openIdClaims: OpenIdClaims, state: State | None) -> Publisher[AuthenticationResponse]:
        return Flux.just(AuthenticationResponse.success("name"))
# end::clazz[]

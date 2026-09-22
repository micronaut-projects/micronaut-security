# tag::clazz[]
from jakarta.inject import Named, Singleton
from micronaut.context.annotation import Requires
from micronaut.security.authentication import AuthenticationResponse
from micronaut.security.oauth2.endpoint.authorization.state import State
from micronaut.security.oauth2.endpoint.token.response import OpenIdAuthenticationMapper, OpenIdClaims, OpenIdTokenResponse
from org.reactivestreams import Publisher
from reactor.core.publisher import Flux


@Singleton
@Named("okta")  # <1>
# end::clazz[]
@Requires(property="docs.classes")
# tag::clazz[]
class OktaAuthenticationMapper(OpenIdAuthenticationMapper):

    def createAuthenticationResponse(self,
                                     providerName: str,  # <2>
                                     tokenResponse: OpenIdTokenResponse,  # <3>
                                     openIdClaims: OpenIdClaims,  # <4>
                                     state: State | None) -> Publisher[AuthenticationResponse]:  # <5>
        return Flux.just(AuthenticationResponse.success("name"))  # <6>
# end::clazz[]

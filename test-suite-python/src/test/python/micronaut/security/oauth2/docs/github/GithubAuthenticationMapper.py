# tag::clazz[]
from jakarta.inject import Named, Singleton
from micronaut.context.annotation import Requires
from micronaut.security.authentication import AuthenticationResponse
from micronaut.security.oauth2.endpoint.authorization.state import State
from micronaut.security.oauth2.endpoint.token.response import OauthAuthenticationMapper, TokenResponse
from org.reactivestreams import Publisher
from reactor.core.publisher import Flux

from .GithubApiClient import GithubApiClient


@Named("github")  # <1>
# end::clazz[]
@Requires(property="docs.classes")
# tag::clazz[]
@Singleton
class GithubAuthenticationMapper(OauthAuthenticationMapper):

    def __init__(self, apiClient: GithubApiClient):  # <2>
        self.apiClient = apiClient

    def createAuthenticationResponse(self, tokenResponse: TokenResponse, state: State | None) -> Publisher[AuthenticationResponse]:  # <3>
        return Flux.from_(self.apiClient.get_user("token " + tokenResponse.getAccessToken())).map(
            lambda user: AuthenticationResponse.success(user.login, ["ROLE_GITHUB"])  # <4>
        )
# end::clazz[]

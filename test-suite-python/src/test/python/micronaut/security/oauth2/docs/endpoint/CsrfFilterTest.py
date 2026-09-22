from typing import Annotated

from jakarta.inject import Inject, Named, Singleton
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpStatus
from micronaut.http.client import DefaultHttpClientConfiguration, HttpClient
from micronaut.http.client.exceptions import HttpClientResponseException
from micronaut.runtime.server import EmbeddedServer
from micronaut.security.authentication import AuthenticationResponse
from micronaut.security.oauth2.endpoint.authorization.state import State
from micronaut.security.oauth2.endpoint.token.response import OauthAuthenticationMapper, TokenResponse
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test
from org.reactivestreams import Publisher
from reactor.core.publisher import Flux


@Property(name="spec.name", value="CsrfFilterTest")
@Property(name="oauth.csrf", value="true")
@Property(name="micronaut.security.authentication", value="cookie")
@Property(name="micronaut.security.oauth2.clients.twitter.authorization.url", value="https://twitter.com/authorize")
@Property(name="micronaut.security.oauth2.clients.twitter.token.url", value="https://twitter.com/token")
@Property(name="micronaut.security.oauth2.clients.twitter.client-id", value="myclient")
@Property(name="micronaut.security.oauth2.clients.twitter.client-secret", value="mysecret")
@MicronautTest
class CsrfFilterTest:
    embeddedServer: Annotated[EmbeddedServer, Inject]

    @Test
    def test_csrf_filter(self):
        configuration = DefaultHttpClientConfiguration()
        configuration.setFollowRedirects(False)
        client = HttpClient.create(self.embeddedServer.getURL(), configuration)
        try:
            client.toBlocking().exchange("/oauth/login/twitter")
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as e:
            assert e.getStatus() == HttpStatus.FORBIDDEN
        finally:
            client.close()


@Singleton
@Named("twitter")
@Requires(property="spec.name", value="CsrfFilterTest")
class TwitterAuthenticationMapper(OauthAuthenticationMapper):

    def createAuthenticationResponse(self, tokenResponse: TokenResponse, state: State | None) -> Publisher[AuthenticationResponse]:
        return Flux.just(AuthenticationResponse.success("twitterUser"))

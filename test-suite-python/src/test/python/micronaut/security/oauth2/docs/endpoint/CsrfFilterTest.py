from typing import Annotated

from jakarta.inject import Inject, Named, Singleton
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpRequest, HttpStatus
from micronaut.http.client import DefaultHttpClientConfiguration, HttpClient
from micronaut.http.client.exceptions import HttpClientResponseException
from micronaut.http.cookie import Cookie
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
        assert self.status(HttpRequest.GET("/oauth/login/twitter")) == HttpStatus.FORBIDDEN

    @Test
    def test_csrf_filter_rejects_a_different_token(self):
        request = HttpRequest.GET("/oauth/login/twitter?_csrf=other-token-fixture").cookie(Cookie.of("_csrf", "token-fixture"))
        assert self.status(request) == HttpStatus.FORBIDDEN

    @Test
    def test_csrf_filter_allows_the_token(self):
        request = HttpRequest.GET("/oauth/login/twitter?_csrf=token-fixture").cookie(Cookie.of("_csrf", "token-fixture"))
        assert self.status(request) == HttpStatus.FOUND

    def status(self, request):
        configuration = DefaultHttpClientConfiguration()
        configuration.setFollowRedirects(False)
        client = HttpClient.create(self.embeddedServer.getURL(), configuration)
        try:
            return client.toBlocking().exchange(request).getStatus()
        except HttpClientResponseException as e:
            return e.getStatus()
        finally:
            client.close()


@Singleton
@Named("twitter")
@Requires(property="spec.name", value="CsrfFilterTest")
class TwitterAuthenticationMapper(OauthAuthenticationMapper):

    def createAuthenticationResponse(self, tokenResponse: TokenResponse, state: State | None) -> Publisher[AuthenticationResponse]:
        return Flux.just(AuthenticationResponse.success("twitterUser"))

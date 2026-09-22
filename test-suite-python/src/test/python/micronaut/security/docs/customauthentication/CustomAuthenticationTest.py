from typing import Annotated

from jakarta.inject import Inject, Singleton
from micronaut.context.annotation import Property, Requires
from micronaut.core.util import StringUtils
from micronaut.http import HttpRequest, MediaType
from micronaut.http.annotation import Controller, Get, Produces
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.security.annotation import Secured
from micronaut.security.authentication import Authentication
from micronaut.security.rules import SecurityRule
from micronaut.security.token.validator import TokenValidator
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test
from org.reactivestreams import Publisher
from reactor.core.publisher import Mono

from .AuthenticationWithEmail import AuthenticationWithEmail


@Property(name="spec.name", value="CustomAuthenticationTest")
@Property(name="micronaut.security.reject-not-found", value=StringUtils.FALSE)
@MicronautTest
class CustomAuthenticationTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_custom_authentication(self):
        client = self.httpClient.toBlocking()
        request = HttpRequest.GET("/custom-authentication").accept(MediaType.TEXT_PLAIN).bearerAuth("xxx")
        email = client.retrieve(request)
        assert email == "sherlock@micronaut.example"


@Requires(property="spec.name", value="CustomAuthenticationTest")
@Controller
class CustomAuthenticationController:
    # tag::method[]
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Produces(MediaType.TEXT_PLAIN)
    @Get("/custom-authentication")
    def index(self, authentication: AuthenticationWithEmail) -> str:
        return authentication.email
    # end::method[]


@Requires(property="spec.name", value="CustomAuthenticationTest")
@Singleton
class CustomAuthenticationProvider(TokenValidator):
    def validateToken(self, token: str, request: HttpRequest) -> Publisher[Authentication]:
        return Mono.just(Authentication.build("sherlock", {"email": "sherlock@micronaut.example"}))

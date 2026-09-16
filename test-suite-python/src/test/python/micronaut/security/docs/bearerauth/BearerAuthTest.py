from typing import Annotated

import java
from jakarta.inject import Inject, Singleton
from micronaut.context.annotation import Property, Requires
from micronaut.core.type import Argument
from micronaut.http import HttpRequest, HttpStatus
from micronaut.http.annotation import Controller, Get
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.security.annotation import Secured
from micronaut.security.authentication import AuthenticationFailureReason, AuthenticationRequest, AuthenticationResponse, UsernamePasswordCredentials
from micronaut.security.authentication.provider import HttpRequestAuthenticationProvider
from micronaut.security.rules import SecurityRule
from micronaut.security.token.render import BearerAccessRefreshToken
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test

from .Book import Book

# TODO(python): java.type needed because the Python class is passed as the runtime type argument of Argument.listOf();
# the Python class object itself is not accepted as a Java Class
BookClass = java.type("micronaut.security.docs.bearerauth.Book")


@Property(name="spec.name", value="BearerAuthTest")
@Property(name="micronaut.security.authentication", value="bearer")
@Property(name="micronaut.security.token.jwt.signatures.secret.generator.secret", value="pleaseChangeThisSecretForANewOne")
@MicronautTest
class BearerAuthTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_bearer_auth_sets_the_authorization_header_with_the_bearer_token(self):
        client = self.httpClient.toBlocking()
        creds = UsernamePasswordCredentials("sherlock", "password")
        rsp = client.exchange(HttpRequest.POST("/login", creds), BearerAccessRefreshToken)
        assert rsp.status() == HttpStatus.OK
        assert rsp.body() is not None

        # tag::bearerAuth[]
        accessToken = rsp.body().getAccessToken()
        books = client.retrieve(HttpRequest.GET("/api/gateway")
                                .bearerAuth(accessToken), Argument.listOf(BookClass))
        # end::bearerAuth[]
        assert books.size() == 2


@Requires(property="spec.name", value="BearerAuthTest")
@Secured(SecurityRule.IS_AUTHENTICATED)
@Controller("/api")
class GatewayController:

    @Get("/gateway")
    def find_all(self) -> list[Book]:
        return [Book("1491950358", "Building Microservices"),
                Book("1680502395", "Release It!")]


@Requires(property="spec.name", value="BearerAuthTest")
@Singleton
class AuthenticationProviderUserPassword(HttpRequestAuthenticationProvider):

    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> AuthenticationResponse:
        if authRequest.getIdentity() == "sherlock" and authRequest.getSecret() == "password":
            return AuthenticationResponse.success("sherlock")
        return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)

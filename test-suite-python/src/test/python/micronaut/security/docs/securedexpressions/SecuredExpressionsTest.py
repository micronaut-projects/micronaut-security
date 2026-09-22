from typing import Annotated

from jakarta.inject import Inject, Singleton
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpRequest, HttpStatus
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.http.client.exceptions import HttpClientResponseException
from micronaut.security.authentication import AuthenticationFailureReason, AuthenticationRequest, AuthenticationResponse
from micronaut.security.authentication.provider import HttpRequestAuthenticationProvider
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="spec.name", value="docexpressions")
@Property(name="micronaut.http.client.read-timeout", value="3600s")
@MicronautTest
class SecuredExpressionsTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_authenticated_by_email(self):
        client = self.httpClient.toBlocking()
        response = client.exchange(HttpRequest.GET("/authenticated/email").basicAuth("sherlock", "password"))
        assert response.status() == HttpStatus.OK

        try:
            client.exchange(HttpRequest.GET("/authenticated/email").basicAuth("moriarty", "password"))
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as e:
            assert e.getStatus() == HttpStatus.FORBIDDEN

        try:
            client.exchange(HttpRequest.GET("/authenticated/email").basicAuth("watson", "password"))
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as e:
            assert e.getStatus() == HttpStatus.UNAUTHORIZED


@Requires(property="spec.name", value="docexpressions")
@Singleton
class AuthenticationProviderUserPassword(HttpRequestAuthenticationProvider):

    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> AuthenticationResponse:
        identity = authRequest.getIdentity()
        if identity == "sherlock":
            return AuthenticationResponse.success("sherlock", ["ROLE_ADMIN"], {"email": "sherlock@micronaut.example"})
        if identity == "moriarty":
            return AuthenticationResponse.success("moriarty", ["ROLE_ADMIN"], {"email": "moriarty@micronaut.example"})
        return AuthenticationResponse.failure(AuthenticationFailureReason.USER_NOT_FOUND)

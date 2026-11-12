from typing import Annotated

from jakarta.inject import Inject, Singleton
from java.util import List
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpRequest, HttpStatus
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.http.client.exceptions import HttpClientResponseException
from micronaut.security.authentication import AuthenticationFailureReason, AuthenticationRequest, AuthenticationResponse
from micronaut.security.authentication.provider import HttpRequestAuthenticationProvider
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="spec.name", value="PermitAllTest")
@MicronautTest
class PermitAllTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_permit_all_endpoint_can_be_accessed_without_authentication(self):
        self.httpClient.toBlocking().exchange(HttpRequest.GET("/example/anonymous"))

    @Test
    def test_roles_allowed_endpoint_requires_one_of_the_roles(self):
        client = self.httpClient.toBlocking()
        try:
            client.exchange(HttpRequest.GET("/example/admin"))
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as e:
            assert e.getStatus() == HttpStatus.UNAUTHORIZED
        try:
            client.exchange(HttpRequest.GET("/example/admin").basicAuth("user", "password"))
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as e:
            assert e.getStatus() == HttpStatus.FORBIDDEN
        client.exchange(HttpRequest.GET("/example/admin").basicAuth("admin", "password"))


@Requires(property="spec.name", value="PermitAllTest")
@Singleton
class AuthenticationProviderUserPassword(HttpRequestAuthenticationProvider):

    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> AuthenticationResponse:
        if authRequest.getIdentity() == "user":
            return AuthenticationResponse.success("user")
        if authRequest.getIdentity() == "admin":
            return AuthenticationResponse.success("admin", List.of("ROLE_ADMIN"))
        return AuthenticationResponse.failure(AuthenticationFailureReason.USER_NOT_FOUND)

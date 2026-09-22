from typing import Annotated

from jakarta.inject import Inject, Singleton
from java.util import List, Map
from micronaut.context.annotation import Property, Requires
from micronaut.core.type import Argument
from micronaut.core.util import StringUtils
from micronaut.http import HttpRequest, HttpStatus
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.http.client.exceptions import HttpClientResponseException
from micronaut.security.authentication import AuthenticationFailureReason, AuthenticationRequest, AuthenticationResponse
from micronaut.security.authentication.provider import HttpRequestAuthenticationProvider
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="endpoints.health.sensitive", value=StringUtils.FALSE)
@Property(name="endpoints.health.enabled", value=StringUtils.TRUE)
@Property(name="endpoints.loggers.sensitive", value=StringUtils.TRUE)
@Property(name="endpoints.loggers.enabled", value=StringUtils.TRUE)
@Property(name="micronaut.security.oauth2.enabled", value=StringUtils.FALSE)
@Property(name="spec.name", value="LoggersTest")
@MicronautTest
class LoggersTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_health_endpoint_is_not_secured(self):
        client = self.httpClient.toBlocking()
        response = client.exchange(HttpRequest.GET("/health"))
        assert response.status() == HttpStatus.OK

    @Test
    def test_loggers_endpoint_is_secured(self):
        client = self.httpClient.toBlocking()
        try:
            client.exchange(HttpRequest.GET("/loggers"))
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as e:
            assert e.getStatus() == HttpStatus.UNAUTHORIZED

    @Test
    def test_loggers_endpoint_is_accessible_for_users_with_role_system(self):
        client = self.httpClient.toBlocking()
        request = HttpRequest.GET("/loggers").basicAuth("system", "password")
        response = client.exchange(request, Argument.of(Map))
        assert response.status() == HttpStatus.OK
        m = response.body()
        assert m.containsKey("levels")
        assert m.containsKey("loggers")

    @Test
    def test_loggers_endpoint_is_not_accessible_for_users_without_role_system(self):
        client = self.httpClient.toBlocking()
        try:
            client.exchange(HttpRequest.GET("/loggers").basicAuth("user", "password"))
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as e:
            assert e.getStatus() == HttpStatus.FORBIDDEN


@Requires(property="spec.name", value="LoggersTest")
@Singleton
class AuthenticationProviderUserPassword(HttpRequestAuthenticationProvider):

    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> AuthenticationResponse:
        if authRequest.getIdentity() == "user":
            return AuthenticationResponse.success("user")
        if authRequest.getIdentity() == "system":
            return AuthenticationResponse.success("system", List.of("ROLE_SYSTEM"))
        return AuthenticationResponse.failure(AuthenticationFailureReason.USER_NOT_FOUND)

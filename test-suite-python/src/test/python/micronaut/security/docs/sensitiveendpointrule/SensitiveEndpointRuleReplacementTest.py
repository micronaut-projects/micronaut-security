from typing import Annotated

from jakarta.inject import Inject, Singleton
from micronaut.context.annotation import Property, Requires
from micronaut.core.util import StringUtils
from micronaut.http import HttpRequest, HttpStatus
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.http.client.exceptions import HttpClientResponseException
from micronaut.security.authentication import AuthenticationFailureReason, AuthenticationRequest, AuthenticationResponse
from micronaut.security.authentication.provider import HttpRequestAuthenticationProvider
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="micronaut.security.oauth2.enabled", value=StringUtils.FALSE)
@Property(name="endpoints.beans.enabled", value=StringUtils.TRUE)
@Property(name="endpoints.beans.sensitive", value=StringUtils.TRUE)
@Property(name="spec.name", value="SensitiveEndpointRuleReplacementTest")
@MicronautTest
class SensitiveEndpointRuleReplacementTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_accessing_a_sensitive_endpoint_with_authentication_and_a_sensitive_endpoint_rule_replacement_works(self):
        client = self.httpClient.toBlocking()
        try:
            client.exchange(HttpRequest.GET("/beans"))
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as e:
            assert e.getStatus() == HttpStatus.UNAUTHORIZED
        client.exchange(HttpRequest.GET("/beans").basicAuth("user", "password"))


@Singleton
@Requires(property="spec.name", value="SensitiveEndpointRuleReplacementTest")
class AuthenticationProviderUserPassword(HttpRequestAuthenticationProvider):

    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> AuthenticationResponse:
        if authRequest.getIdentity() == "user":
            return AuthenticationResponse.success("user")
        return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)

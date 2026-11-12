from typing import Annotated

from jakarta.inject import Inject, Singleton
from java.util import Map
from micronaut.context.annotation import Property, Requires
from micronaut.core.type import Argument
from micronaut.http import HttpRequest, HttpStatus
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.security.authentication import AuthenticationFailureReason, AuthenticationRequest, AuthenticationResponse
from micronaut.security.authentication.provider import HttpRequestAuthenticationProvider
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="spec.name", value="PrincipalParamTest")
@MicronautTest
class PrincipalParamTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_principal_can_be_used_as_a_controller_parameter_to_get_the_logged_in_user(self):
        client = self.httpClient.toBlocking()
        rsp = client.exchange(HttpRequest.GET("/user/myinfo"), Argument.of(Map))
        assert rsp.status() == HttpStatus.OK
        assert not rsp.body().containsKey("username")

        rsp = client.exchange(HttpRequest.GET("/user/myinfo").basicAuth("user", "password"), Argument.of(Map))
        assert rsp.status() == HttpStatus.OK
        assert rsp.body().containsKey("username")
        assert rsp.body().get("username") == "user"


@Requires(property="spec.name", value="PrincipalParamTest")
@Singleton
class AuthenticationProviderUserPassword(HttpRequestAuthenticationProvider):

    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> AuthenticationResponse:
        if authRequest.getIdentity() == "user" and authRequest.getSecret() == "password":
            return AuthenticationResponse.success("user")
        return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)

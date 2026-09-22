from typing import Annotated

import java
from jakarta.inject import Inject, Singleton
from micronaut.context.annotation import Property, Requires
from micronaut.core.type import Argument
from micronaut.http import HttpRequest
from micronaut.http.annotation import Controller, Get
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.security.annotation import Secured
from micronaut.security.authentication import Authentication, AuthenticationRequest, AuthenticationResponse, ClientAuthentication
from micronaut.security.authentication.provider import HttpRequestAuthenticationProvider
from micronaut.security.context import SecurityContextHolder
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test

from .RunAsService import RunAsService


@Property(name="spec.name", value="RunAsTest")
@MicronautTest
class RunAsTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_verify_you_can_use_the_run_as_annotation_to_change_the_security_context_holder_for_the_scope_of_a_class(self):
        client = self.httpClient.toBlocking()
        authentications = client.retrieve(
            HttpRequest.GET("/runAs").basicAuth("john", "ilikedaenerys"),
            Argument.listOf(ClientAuthentication),
        )
        authentication = authentications.get(0)
        assert authentication is not None
        assert authentication.getName() == "aegon"
        assert list(authentication.getRoles()) == ["ROLE_STARK", "TARGARYEN"]
        attributes = authentication.getAttributes()
        assert attributes.get("family_name") == "Targaryen"
        assert attributes.get("given_name") == "Aegon"
        assert list(attributes.get("roles")) == ["ROLE_STARK", "TARGARYEN"]

        authentication = authentications.get(1)
        assert authentication is not None
        assert authentication.getName() == "john"
        assert list(authentication.getRoles()) == ["ROLE_STARK"]
        attributes = authentication.getAttributes()
        assert attributes.get("family_name") == "Snow"
        assert attributes.get("given_name") == "John"
        assert list(attributes.get("roles")) == ["ROLE_STARK"]


@Requires(property="spec.name", value="RunAsTest")
@Singleton
class RunAsProvider(HttpRequestAuthenticationProvider):
    def authenticate(self, requestContext: HttpRequest, authRequest: AuthenticationRequest) -> AuthenticationResponse:
        return AuthenticationResponse.success(
            "john",
            ["ROLE_STARK"],
            {"family_name": "Snow", "given_name": "John"},
        )


@Requires(property="spec.name", value="RunAsTest")
@Singleton
class AuthService:
    def auth(self) -> Authentication:
        return SecurityContextHolder.getSecurityContext().getAuthentication()


@Requires(property="spec.name", value="RunAsTest")
@Controller("/runAs")
class RunAsController:
    def __init__(self, runAuthService: RunAsService, authService: AuthService):
        self.runAuthService = runAuthService
        self.authService = authService

    @Secured("ROLE_STARK")
    @Get
    def index(self, authentication: Authentication) -> list[Authentication]:
        return [self.runAuthService.change_auth(), self.authService.auth()]

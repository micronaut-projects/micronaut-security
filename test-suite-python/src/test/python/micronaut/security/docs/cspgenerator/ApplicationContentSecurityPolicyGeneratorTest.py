from typing import Annotated

from jakarta.inject import Inject
from java.lang import String
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpRequest
from micronaut.http.annotation import Controller, Get
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.security.annotation import Secured
from micronaut.security.rules import SecurityRule
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="spec.name", value="ApplicationContentSecurityPolicyGeneratorTest")
@MicronautTest
class ApplicationContentSecurityPolicyGeneratorTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_the_custom_generator_defines_the_response_header(self):
        response = self.httpClient.toBlocking().exchange(HttpRequest.GET("/csp-generator"), String)

        assert response.header("Content-Security-Policy") == "default-src 'self'; object-src 'none'"


@Requires(property="spec.name", value="ApplicationContentSecurityPolicyGeneratorTest")
@Controller("/csp-generator")
class CspGeneratorController:

    @Secured(SecurityRule.IS_ANONYMOUS)
    @Get
    def index(self) -> str:
        return "ok"

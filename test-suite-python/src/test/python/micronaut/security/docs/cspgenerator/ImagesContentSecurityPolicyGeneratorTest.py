from typing import Annotated

from jakarta.inject import Inject
from java.lang import String
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpRequest
from micronaut.http.annotation import Controller, Get
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.security.annotation import Secured
from micronaut.security.csp import ContentSecurityPolicy
from micronaut.security.rules import SecurityRule
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="spec.name", value="ImagesContentSecurityPolicyGeneratorTest")
@Property(name="micronaut.security.csp.script-src.self", value="true")
@MicronautTest
class ImagesContentSecurityPolicyGeneratorTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_the_overridden_directive_replaces_the_configured_one(self):
        response = self.httpClient.toBlocking().exchange(HttpRequest.GET("/csp-generator-images"), String)

        policy = ContentSecurityPolicy.of(response)
        assert policy.imgSrc().toHeaderValue() == "img-src 'self' https://images.example.com"
        assert policy.scriptSrc().toHeaderValue() == "script-src 'self'"


@Requires(property="spec.name", value="ImagesContentSecurityPolicyGeneratorTest")
@Controller("/csp-generator-images")
class ImagesController:

    @Secured(SecurityRule.IS_ANONYMOUS)
    @Get
    def index(self) -> str:
        return "ok"

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


@Property(name="spec.name", value="UpgradingContentSecurityPolicyGeneratorTest")
@Property(name="micronaut.security.csp.script-src.self", value="true")
@MicronautTest
class UpgradingContentSecurityPolicyGeneratorTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_the_subclass_appends_a_directive_that_the_configuration_does_not_expose(self):
        response = self.httpClient.toBlocking().exchange(HttpRequest.GET("/csp-generator-upgrade"), String)

        policy = ContentSecurityPolicy.of(response)
        assert policy.upgradeInsecureRequests() is not None
        assert policy.scriptSrc().toHeaderValue() == "script-src 'self'"


@Requires(property="spec.name", value="UpgradingContentSecurityPolicyGeneratorTest")
@Controller("/csp-generator-upgrade")
class UpgradeController:

    @Secured(SecurityRule.IS_ANONYMOUS)
    @Get
    def index(self) -> str:
        return "ok"

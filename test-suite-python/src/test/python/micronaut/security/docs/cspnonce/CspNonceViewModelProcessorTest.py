import re
from typing import Annotated

from jakarta.inject import Inject
from java.lang import String
from java.util import Map
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpRequest, MediaType
from micronaut.http.annotation import Controller, Get, Produces
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.security.annotation import Secured
from micronaut.security.rules import SecurityRule
from micronaut.test.extensions.junit5.annotation import MicronautTest
from micronaut.views import ModelAndView
from org.junit.jupiter.api import Test


@Property(name="spec.name", value="CspNonceViewModelProcessorTest")
@Property(name="micronaut.security.csp.script-src.nonce", value="true")
@MicronautTest
class CspNonceViewModelProcessorTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_the_view_renders_the_nonce_of_the_response_header(self):
        response = self.httpClient.toBlocking().exchange(HttpRequest.GET("/csp-nonce"), String)

        match = re.search(r'<script nonce="([^"]+)">', str(response.body()))
        assert match is not None, "the view must render the nonce"
        contentSecurityPolicy = response.header("Content-Security-Policy")
        assert contentSecurityPolicy is not None
        assert "'nonce-" + match.group(1) + "'" in str(contentSecurityPolicy)


@Requires(property="spec.name", value="CspNonceViewModelProcessorTest")
@Controller("/csp-nonce")
class CspNonceController:

    @Secured(SecurityRule.IS_ANONYMOUS)
    @Produces(MediaType.TEXT_HTML)
    @Get
    def index(self) -> ModelAndView[Map[str, object]]:
        return ModelAndView("csp-nonce", Map.of("title", "CSP nonce"))

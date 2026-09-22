from typing import Annotated

from jakarta.inject import Inject
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpRequest
from micronaut.http.annotation import Controller, Get
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.http.client.exceptions import HttpClientResponseException
from micronaut.security.annotation import Secured
from micronaut.security.rules import SecurityRule
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="spec.name", value="RejectionHandlerOverrideTest")
@MicronautTest
class RejectionHandlerOverrideTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_the_rejection_handler_can_be_overridden(self):
        try:
            self.httpClient.toBlocking().exchange(HttpRequest.GET("/rejection-handler"))
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as ex:
            assert ex.getResponse().header("X-Reason") == "Example Header"


@Requires(property="spec.name", value="RejectionHandlerOverrideTest")
@Secured(SecurityRule.IS_AUTHENTICATED)
@Controller("/rejection-handler")
class SecuredResource:

    @Get
    def foo(self) -> str:
        return ""

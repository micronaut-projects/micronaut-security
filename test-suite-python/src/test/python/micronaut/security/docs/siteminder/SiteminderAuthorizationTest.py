import uuid
from typing import Annotated

from jakarta.inject import Inject
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpRequest, MediaType
from micronaut.http.annotation import Controller, Get, Produces
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.security.annotation import Secured
from micronaut.security.authentication import Authentication
from micronaut.security.rules import SecurityRule
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test

from .SiteminderAuthenticationFetcher import SITEMINDER_USER_HEADER


@Property(name="spec.name", value="SiteminderAuthorizationTest")
@MicronautTest
class SiteminderAuthorizationTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_custom_siteminder_authentication_fetcher(self):
        username = str(uuid.uuid4())
        request = HttpRequest.GET("/sm").header(SITEMINDER_USER_HEADER, username)
        assert self.httpClient.toBlocking().retrieve(request) == username


@Requires(property="spec.name", value="SiteminderAuthorizationTest")
@Secured(SecurityRule.IS_AUTHENTICATED)
@Controller("/sm")
class MyController:

    @Produces(MediaType.TEXT_PLAIN)
    @Get
    def username(self, authentication: Authentication) -> str:
        return authentication.getName()

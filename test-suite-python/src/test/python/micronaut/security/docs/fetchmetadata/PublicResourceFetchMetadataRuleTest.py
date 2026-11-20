from typing import Annotated

from jakarta.inject import Inject
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpHeaders, HttpRequest, HttpStatus, MediaType
from micronaut.http.annotation import Controller, Get, Produces
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.http.client.exceptions import HttpClientResponseException
from micronaut.security.annotation import Secured
from micronaut.security.rules import SecurityRule
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


def cross_site_image(path: str):
    return (HttpRequest.GET(path)
            .header(HttpHeaders.SEC_FETCH_SITE, "cross-site")
            .header(HttpHeaders.SEC_FETCH_MODE, "no-cors")
            .header(HttpHeaders.SEC_FETCH_DEST, "image"))


@Property(name="spec.name", value="PublicResourceFetchMetadataRuleTest")
@MicronautTest
class PublicResourceFetchMetadataRuleTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_cross_site_subresource_requests_reach_only_the_public_resource(self):
        client = self.httpClient.toBlocking()
        assert client.exchange(cross_site_image("/favicon.ico")).getStatus() == HttpStatus.OK
        try:
            client.exchange(cross_site_image("/account"))
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as e:
            assert e.getStatus() == HttpStatus.FORBIDDEN


@Requires(property="spec.name", value="PublicResourceFetchMetadataRuleTest")
@Secured(SecurityRule.IS_ANONYMOUS)
@Controller
class PublicResourceController:

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/favicon.ico")
    def favicon(self) -> str:
        return "icon"

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/account")
    def account(self) -> str:
        return "account"

from typing import Annotated

from jakarta.inject import Inject
from micronaut.context.annotation import Property, Requires
from micronaut.http import HttpRequest, HttpStatus
from micronaut.http.annotation import Controller, Get
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.http.client.exceptions import HttpClientResponseException
from micronaut.security.annotation import Secured
from micronaut.security.rules import SecurityRule
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@Property(name="spec.name", value="AuthenticationProviderTest")
@MicronautTest
class AuthenticationProviderTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_auth_provider(self):
        client = self.httpClient.toBlocking()
        json = client.retrieve(self.create_request("user", "password"))
        assert json == '{"message":"Hello World"}'
        try:
            client.retrieve(self.create_request("user", "wrong"))
            assert False, "HttpClientResponseException expected"
        except HttpClientResponseException as e:
            assert e.getStatus() == HttpStatus.UNAUTHORIZED

    def create_request(self, user_name: str, password: str):
        return HttpRequest.GET("/messages").basicAuth(user_name, password)


@Requires(property="spec.name", value="AuthenticationProviderTest")
@Controller("/messages")
class HelloWorldController:

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Get
    def index(self) -> dict:
        return {"message": "Hello World"}

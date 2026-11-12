import base64

from micronaut.http import HttpRequest
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test


@MicronautTest(startApplication=False)
class BasicAuthTest:

    @Test
    def test_basic_auth_sets_the_authorization_header_with_basic_base64_username_and_password(self):
        # tag::basicAuth[]
        request = HttpRequest.GET("/home").basicAuth("sherlock", "password")
        # end::basicAuth[]
        encoded = base64.b64encode(b"sherlock:password").decode()
        assert request.getHeaders().get("Authorization") == "Basic " + encoded

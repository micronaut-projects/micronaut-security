from typing import Annotated

from jakarta.inject import Inject
from micronaut.context.annotation import Property
from micronaut.http import HttpRequest, HttpStatus
from micronaut.http.client import HttpClient
from micronaut.http.client.annotation import Client
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test

REPORTS = """
[{
  "type": "csp-violation",
  "age": 10,
  "url": "https://example.com/page",
  "user_agent": "Example Browser",
  "body": {
    "documentURL": "https://example.com/page",
    "blockedURL": "https://evil.example/script.js",
    "effectiveDirective": "script-src-elem",
    "originalPolicy": "script-src 'none'",
    "disposition": "enforce",
    "statusCode": 200
  }
}]
"""


@Property(name="spec.name", value="ApplicationCspReportHandlerTest")
@Property(name="micronaut.security.csp.report-to.enabled", value="true")
@Property(name="micronaut.security.csp.report-to.group", value="csp")
@Property(name="micronaut.security.intercept-url-map[0].pattern", value="/csp/report")
@Property(name="micronaut.security.intercept-url-map[0].http-method", value="POST")
@Property(name="micronaut.security.intercept-url-map[0].access[0]", value="isAnonymous()")
@MicronautTest
class ApplicationCspReportHandlerTest:
    httpClient: Annotated[HttpClient, Inject, Client("/")]

    @Test
    def test_the_report_endpoint_accepts_reports_when_a_handler_exists(self):
        response = self.httpClient.toBlocking().exchange(
            HttpRequest.POST("/csp/report", REPORTS).contentType("application/reports+json"))

        assert response.getStatus() == HttpStatus.NO_CONTENT

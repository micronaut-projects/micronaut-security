# tag::clazz[]
from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.http import HttpRequest
from micronaut.security.csp.report import ContentSecurityPolicyReport, ContentSecurityPolicyReportHandler

# end::clazz[]
@Requires(property="spec.name", value="ApplicationCspReportHandlerTest")
# tag::clazz[]
@Singleton
class ApplicationCspReportHandler(ContentSecurityPolicyReportHandler):

    def handle(self, reports: list[ContentSecurityPolicyReport], request: HttpRequest) -> None:
        # Validate, sanitize, and send the reports to application storage or monitoring.
        pass
# end::clazz[]

package io.micronaut.security.docs.cspreport

//tag::clazz[]
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.security.csp.report.ContentSecurityPolicyReport
import io.micronaut.security.csp.report.ContentSecurityPolicyReportHandler
import jakarta.inject.Singleton

//end::clazz[]
@Requires(property = "spec.name", value = "ApplicationCspReportHandlerTest")
//tag::clazz[]
@Singleton
class ApplicationCspReportHandler : ContentSecurityPolicyReportHandler {

    override fun handle(reports: List<ContentSecurityPolicyReport>, request: HttpRequest<*>) {
        // Validate, sanitize, and send the reports to application storage or monitoring.
    }
}
//end::clazz[]

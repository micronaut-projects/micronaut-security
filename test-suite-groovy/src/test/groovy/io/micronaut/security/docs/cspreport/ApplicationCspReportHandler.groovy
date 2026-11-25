package io.micronaut.security.docs.cspreport

import io.micronaut.context.annotation.Requires
//tag::clazz[]
import io.micronaut.http.HttpRequest
import io.micronaut.security.csp.report.ContentSecurityPolicyReport
import io.micronaut.security.csp.report.ContentSecurityPolicyReportHandler
import jakarta.inject.Singleton

//end::clazz[]
@Requires(property = "spec.name", value = "ApplicationCspReportHandlerTest")
//tag::clazz[]
@Singleton
class ApplicationCspReportHandler implements ContentSecurityPolicyReportHandler {

    @Override
    void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request) {
        // Validate, sanitize, and send the reports to application storage or monitoring.
    }
}
//end::clazz[]

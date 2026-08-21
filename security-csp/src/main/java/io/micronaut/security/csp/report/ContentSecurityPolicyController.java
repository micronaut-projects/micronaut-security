/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.csp.report;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Status;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * Receives Content Security Policy reports delivered through the Reporting API.
 *
 * <p>User agents deliver one or more reports as a JSON array using the
 * {@code application/reports+json} media type. Each accepted batch is passed to the configured
 * {@link ContentSecurityPolicyReportHandler} bean. The handler must treat every field as untrusted
 * input.</p>
 *
 * @see <a href="https://w3c.github.io/reporting/#try-delivery">Reporting API report delivery</a>
 */
@Controller("${" + ContentSecurityPolicyControllerConfigurationProperties.PREFIX + ".path:/csp/report}")
@Requires(beans = ContentSecurityPolicyReportHandler.class)
@Requires(beans = ContentSecurityPolicyControllerConfiguration.class)
class ContentSecurityPolicyController {
    static final String APPLICATION_REPORTS_JSON = "application/reports+json";

    private final ContentSecurityPolicyReportHandler handler;

    /**
     * Creates the controller with the application's report handler.
     *
     * @param handler processes each accepted report batch
     */
    ContentSecurityPolicyController(ContentSecurityPolicyReportHandler handler) {
        this.handler = handler;
    }

    /**
     * Accepts a batch of reports and acknowledges successful delivery without a response body.
     *
     * @param reports reports serialized by the user agent
     * @param request request that delivered the reports
     */
    @Post
    @Consumes(APPLICATION_REPORTS_JSON)
    @Status(HttpStatus.NO_CONTENT)
    void report(@Body @NotNull List<@NotNull @Valid ContentSecurityPolicyReport> reports,
                HttpRequest<?> request) {
        List<ContentSecurityPolicyReport> immutableReports = List.copyOf(reports);
        handler.handle(immutableReports, request);
    }
}

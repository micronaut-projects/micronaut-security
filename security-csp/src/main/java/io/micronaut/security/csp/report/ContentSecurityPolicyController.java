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
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.codec.CodecException;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

import java.io.ByteArrayInputStream;
import java.util.List;

/**
 * Receives Content Security Policy reports delivered through the Reporting API.
 *
 * <p>User agents deliver one or more reports as a JSON array using the
 * {@code application/reports+json} media type. The controller is registered only when the
 * {@code report-to} directive is enabled and a {@link ContentSecurityPolicyReportHandler} bean exists.
 * Each accepted batch that contains CSP reports is passed to the configured
 * {@link ContentSecurityPolicyReportHandler} bean.</p>
 *
 * <p>The body is decoded on the blocking executor, not on the event loop: the endpoint is anonymous,
 * so a large or malformed body must not be parsed on a thread that serves other connections. The
 * handler runs on the same executor, so it may perform I/O. It must treat every field as untrusted
 * input.</p>
 *
 * @see <a href="https://w3c.github.io/reporting/#try-delivery">Reporting API report delivery</a>
 */
@Controller("${" + ContentSecurityPolicyControllerConfigurationProperties.PREFIX + ".path:"
    + ContentSecurityPolicyControllerConfigurationProperties.DEFAULT_PATH + "}")
@Requires(beans = ContentSecurityPolicyReportHandler.class)
@Requires(condition = ReportToEnabledCondition.class)
@Requires(beans = ContentSecurityPolicyControllerConfiguration.class)
@Internal
class ContentSecurityPolicyController {
    static final String APPLICATION_REPORTS_JSON = "application/reports+json";
    private static final MediaType REPORTS_JSON = MediaType.of(APPLICATION_REPORTS_JSON);
    private static final Argument<List<ContentSecurityPolicyReport>> REPORTS = Argument.listOf(ContentSecurityPolicyReport.class);

    private final ContentSecurityPolicyReportHandler handler;
    private final ContentSecurityPolicyReportBodyReader reader;

    /**
     * Creates the controller with the application's report handler.
     *
     * @param handler processes each accepted report batch
     * @param reader decodes and checks a report batch
     */
    ContentSecurityPolicyController(ContentSecurityPolicyReportHandler handler,
                                    ContentSecurityPolicyReportBodyReader reader) {
        this.handler = handler;
        this.reader = reader;
    }

    /**
     * Accepts a batch of reports and acknowledges successful delivery without a response body.
     *
     * @param body the request body
     * @param request request that delivered the reports
     * @return HTTP 204 for an accepted batch, or HTTP 400 for a body that is not a valid batch
     */
    @ExecuteOn(TaskExecutors.BLOCKING)
    @Post
    @Consumes(APPLICATION_REPORTS_JSON)
    HttpResponse<?> report(@Body byte[] body, HttpRequest<?> request) {
        List<ContentSecurityPolicyReport> reports;
        try {
            reports = reader.read(REPORTS, REPORTS_JSON, request.getHeaders(), new ByteArrayInputStream(body));
        } catch (CodecException e) {
            // The reader logged the reason; the response does not repeat it to the anonymous client.
            return HttpResponse.badRequest();
        }
        if (reports == null) {
            return HttpResponse.badRequest();
        }
        if (!reports.isEmpty()) {
            // An empty batch, or one with only non-CSP reports, leaves the handler nothing to do.
            handler.handle(List.copyOf(reports), request);
        }
        return HttpResponse.noContent();
    }
}

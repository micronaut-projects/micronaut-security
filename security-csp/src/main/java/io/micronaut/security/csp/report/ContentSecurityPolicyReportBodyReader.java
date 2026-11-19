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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.type.Argument;
import io.micronaut.core.type.Headers;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.body.MessageBodyReader;
import io.micronaut.http.codec.CodecException;
import io.micronaut.json.JsonMapper;
import io.micronaut.json.tree.JsonNode;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Decodes the Reporting API's dedicated JSON media type.
 */
@Internal
@Requires(classes = JsonMapper.class)
@Requires(beans = JsonMapper.class)
@Singleton
@Consumes(ContentSecurityPolicyController.APPLICATION_REPORTS_JSON)
final class ContentSecurityPolicyReportBodyReader implements MessageBodyReader<List<ContentSecurityPolicyReport>> {
    private static final Logger LOG = LoggerFactory.getLogger(ContentSecurityPolicyReportBodyReader.class);
    private final JsonMapper jsonMapper;

    ContentSecurityPolicyReportBodyReader(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    @Override
    public @Nullable List<ContentSecurityPolicyReport> read(Argument<List<ContentSecurityPolicyReport>> type,
                                                            @Nullable MediaType mediaType,
                                                            Headers httpHeaders,
                                                            InputStream inputStream) throws CodecException {
        try {
            List<@Nullable SerializedContentSecurityPolicyReport> serializedReports = jsonMapper.readValue(
                inputStream,
                Argument.listOf(SerializedContentSecurityPolicyReport.class)
            );
            if (serializedReports == null) {
                return null;
            }
            List<ContentSecurityPolicyReport> reports = new ArrayList<>(serializedReports.size());
            for (@Nullable SerializedContentSecurityPolicyReport report : serializedReports) {
                ContentSecurityPolicyReport cspReport = toReport(report);
                if (cspReport != null) {
                    reports.add(cspReport);
                }
            }
            return reports;
        } catch (IOException e) {
            throw new CodecException("Error decoding Reporting API request body: " + e.getMessage(), e);
        }
    }

    /**
     * Converts one serialized report.
     *
     * <p>A Reporting API endpoint group can receive reports of other types, such as
     * {@code deprecation} or {@code intervention}, when it is shared with other policies. Those
     * reports are skipped so that the CSP reports delivered in the same batch are still accepted.</p>
     *
     * @param report the serialized report
     * @return the CSP report, or {@code null} when the report has a non-CSP type
     * @throws IOException if the report body cannot be decoded
     */
    private @Nullable ContentSecurityPolicyReport toReport(@Nullable SerializedContentSecurityPolicyReport report) throws IOException {
        if (report == null) {
            throw new CodecException("A Content Security Policy report batch must not contain null reports");
        }
        String reportType = report.type();
        if (reportType == null) {
            throw new CodecException("A Content Security Policy report type is required");
        }
        if (!ContentSecurityPolicyReport.TYPE_CSP_VIOLATION.equals(reportType)
            && !ContentSecurityPolicyReport.TYPE_CSP_HASH.equals(reportType)) {
            if (LOG.isDebugEnabled()) {
                // The type is untrusted input, so it is not logged.
                LOG.debug("Skipping a report whose type is not a Content Security Policy report type");
            }
            return null;
        }
        JsonNode serializedBody = report.body();
        if (serializedBody == null || serializedBody.isNull()) {
            throw new CodecException("A Content Security Policy report body is required");
        }
        ContentSecurityPolicyReportBody body = ContentSecurityPolicyReport.TYPE_CSP_VIOLATION.equals(reportType)
            ? jsonMapper.readValueFromTree(serializedBody, ContentSecurityPolicyViolationReportBody.class)
            : jsonMapper.readValueFromTree(serializedBody, ContentSecurityPolicyHashReportBody.class);
        if (body == null) {
            throw new CodecException("A Content Security Policy report body is required");
        }
        return new ContentSecurityPolicyReport(
            report.age(),
            reportType,
            report.url(),
            report.userAgent(),
            body
        );
    }
}

@Serdeable
record SerializedContentSecurityPolicyReport(
    Long age,
    String type,
    String url,
    @JsonProperty("user_agent") String userAgent,
    @Nullable JsonNode body
) {
}

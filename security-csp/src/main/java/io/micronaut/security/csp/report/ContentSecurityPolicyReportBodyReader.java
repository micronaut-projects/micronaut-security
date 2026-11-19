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
import io.micronaut.core.util.StringUtils;
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
    /** Maximum reports in one batch; Chromium queues at most 100 reports. */
    static final int MAX_REPORTS = 100;
    static final int MAX_URL_LENGTH = 8192;
    static final int MAX_POLICY_LENGTH = 65_536;
    static final int MAX_USER_AGENT_LENGTH = 1024;
    static final int MAX_SAMPLE_LENGTH = 1024;
    static final int MAX_TOKEN_LENGTH = 256;
    private static final Logger LOG = LoggerFactory.getLogger(ContentSecurityPolicyReportBodyReader.class);
    private static final int MAX_STATUS_CODE = 65_535;
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
            if (serializedReports.size() > MAX_REPORTS) {
                throw new CodecException("A Reporting API batch must not contain more than " + MAX_REPORTS + " reports");
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
        validateEnvelope(report);
        if (body instanceof ContentSecurityPolicyViolationReportBody violation) {
            validate(violation);
        } else if (body instanceof ContentSecurityPolicyHashReportBody hash) {
            validate(hash);
        }
        return new ContentSecurityPolicyReport(
            report.age(),
            reportType,
            report.url(),
            report.userAgent(),
            body
        );
    }

    /*
     * The checks below always run, unlike the bean-validation constraints on the report records,
     * which need micronaut-validation at runtime. They keep the documented non-null contract of the
     * records and bound the size of anonymous, attacker-controllable input.
     */

    private static void validateEnvelope(SerializedContentSecurityPolicyReport report) {
        if (report.age() == null || report.age() < 0) {
            throw new CodecException("A Content Security Policy report requires a non-negative age");
        }
        requireText("url", report.url(), MAX_URL_LENGTH);
        if (report.userAgent() == null) {
            throw new CodecException("A Content Security Policy report requires a user_agent");
        }
        requireLength("user_agent", report.userAgent(), MAX_USER_AGENT_LENGTH);
    }

    private static void validate(ContentSecurityPolicyViolationReportBody body) {
        requireText("documentURL", body.documentUrl(), MAX_URL_LENGTH);
        requireLength("referrer", body.referrer(), MAX_URL_LENGTH);
        requireLength("blockedURL", body.blockedUrl(), MAX_URL_LENGTH);
        requireText("effectiveDirective", body.effectiveDirective(), MAX_TOKEN_LENGTH);
        requireText("originalPolicy", body.originalPolicy(), MAX_POLICY_LENGTH);
        requireLength("sourceFile", body.sourceFile(), MAX_URL_LENGTH);
        requireLength("sample", body.sample(), MAX_SAMPLE_LENGTH);
        if (body.disposition() == null) {
            throw new CodecException("A Content Security Policy violation report requires a disposition");
        }
        if (body.statusCode() == null || body.statusCode() < 0 || body.statusCode() > MAX_STATUS_CODE) {
            throw new CodecException("A Content Security Policy violation report requires a valid statusCode");
        }
        if ((body.lineNumber() != null && body.lineNumber() < 0) || (body.columnNumber() != null && body.columnNumber() < 0)) {
            throw new CodecException("A Content Security Policy violation report must not have negative line or column numbers");
        }
    }

    private static void validate(ContentSecurityPolicyHashReportBody body) {
        requireLength("documentURL", body.documentUrl(), MAX_URL_LENGTH);
        requireLength("subresourceURL", body.subresourceUrl(), MAX_URL_LENGTH);
        requireText("hash", body.hash(), MAX_TOKEN_LENGTH);
        requireLength("destination", body.destination(), MAX_TOKEN_LENGTH);
        requireLength("type", body.type(), MAX_TOKEN_LENGTH);
    }

    private static void requireText(String field, @Nullable String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            throw new CodecException("A Content Security Policy report requires " + field);
        }
        requireLength(field, value, maxLength);
    }

    private static void requireLength(String field, @Nullable String value, int maxLength) {
        if (value != null && value.length() > maxLength) {
            throw new CodecException("A Content Security Policy report field " + field + " must not be longer than " + maxLength + " characters");
        }
    }
}

@Serdeable
record SerializedContentSecurityPolicyReport(
    @Nullable Long age,
    @Nullable String type,
    @Nullable String url,
    @JsonProperty("user_agent") @Nullable String userAgent,
    @Nullable JsonNode body
) {
}

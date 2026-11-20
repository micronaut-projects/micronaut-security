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
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.body.MessageBodyReader;
import io.micronaut.http.codec.CodecException;
import io.micronaut.json.JsonMapper;
import io.micronaut.json.tree.JsonNode;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

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
    /**
     * Maximum size of a report batch body. Browsers send a few kilobytes; the limit stops a large
     * body from being parsed into a JSON tree, which needs many times its size in memory, on this
     * unauthenticated endpoint.
     */
    static final int MAX_BODY_BYTES = 1024 * 1024;
    private static final String BODY_TOO_LARGE = "A Reporting API batch must not be larger than " + MAX_BODY_BYTES + " bytes";
    private static final Logger LOG = LoggerFactory.getLogger(ContentSecurityPolicyReportBodyReader.class);
    private static final int MAX_STATUS_CODE = 65_535;
    /**
     * The largest line or column number, the range of the {@code unsigned long} the Reporting API uses.
     */
    private static final long MAX_POSITION = 4_294_967_295L;
    /**
     * The message of a body that cannot be decoded. It does not repeat the decoder's message, which
     * names internal types, in the response of this anonymous endpoint.
     */
    private static final String INVALID_BODY = "The body is not a valid Reporting API batch";
    private static final long WARNING_INTERVAL_NANOS = TimeUnit.MINUTES.toNanos(1);
    private final JsonMapper jsonMapper;
    private final LongSupplier nanoTime;
    private final AtomicLong nextWarning;

    @Inject
    ContentSecurityPolicyReportBodyReader(JsonMapper jsonMapper) {
        this(jsonMapper, System::nanoTime);
    }

    /**
     * Creates the reader with the clock that rate-limits the warnings about rejected batches.
     *
     * @param jsonMapper decodes the request body
     * @param nanoTime returns the current value of a monotonic clock in nanoseconds, like {@link System#nanoTime()}
     */
    ContentSecurityPolicyReportBodyReader(JsonMapper jsonMapper, LongSupplier nanoTime) {
        this.jsonMapper = jsonMapper;
        this.nanoTime = nanoTime;
        this.nextWarning = new AtomicLong(nanoTime.getAsLong());
    }

    @Override
    public @Nullable List<ContentSecurityPolicyReport> read(Argument<List<ContentSecurityPolicyReport>> type,
                                                            @Nullable MediaType mediaType,
                                                            Headers httpHeaders,
                                                            InputStream inputStream) throws CodecException {
        if (contentLength(httpHeaders) > MAX_BODY_BYTES) {
            throw rejected(null, BODY_TOO_LARGE, new CodecException(BODY_TOO_LARGE));
        }
        List<@Nullable SerializedContentSecurityPolicyReport> serializedReports;
        try {
            serializedReports = jsonMapper.readValue(new BoundedInputStream(inputStream), Argument.listOf(SerializedContentSecurityPolicyReport.class));
        } catch (IOException | RuntimeException e) {
            if (isBodyTooLarge(e)) {
                throw rejected(null, BODY_TOO_LARGE, new CodecException(BODY_TOO_LARGE, e));
            }
            throw rejected(null, "the body is not a JSON array of Reporting API reports",
                new CodecException(INVALID_BODY, e));
        }
        if (serializedReports == null) {
            return null;
        }
        try {
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
        } catch (CodecException e) {
            throw rejected(serializedReports.size(), e.getMessage(), e);
        } catch (IOException e) {
            throw rejected(serializedReports.size(), "a report body could not be decoded",
                new CodecException(INVALID_BODY, e));
        }
    }

    /**
     * Tests whether reading failed because the body exceeds {@link #MAX_BODY_BYTES}. The JSON parser
     * may wrap the exception of the bounded stream.
     *
     * @param failure the exception thrown while reading the body
     * @return whether the body is too large
     */
    private static boolean isBodyTooLarge(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof BodyTooLargeException) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the declared length of the body.
     *
     * @param headers the request headers
     * @return the {@code Content-Length}, or {@code -1} when it is absent or not a number
     */
    private static long contentLength(Headers headers) {
        String contentLength = headers.get(HttpHeaders.CONTENT_LENGTH);
        if (contentLength == null) {
            return -1;
        }
        try {
            return Long.parseLong(contentLength.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * Logs that a batch is rejected with HTTP 400, so that operators notice reports that never reach
     * the handler. The first rejection in each minute is logged at WARN and the others at DEBUG, so a
     * misbehaving client cannot flood the log. Report contents are untrusted and never logged; the
     * reason is one of the reader's own messages.
     *
     * @param reports the number of reports in the batch, or {@code null} if the body could not be parsed
     * @param reason why the batch is rejected
     * @param exception the exception that rejects the batch
     * @return {@code exception}, to be thrown by the caller
     */
    private CodecException rejected(@Nullable Integer reports, String reason, CodecException exception) {
        String batch = reports == null ? "a batch of Content Security Policy reports" : "a batch of " + reports + " Content Security Policy reports";
        long now = nanoTime.getAsLong();
        long next = nextWarning.get();
        if (now - next >= 0 && nextWarning.compareAndSet(next, now + WARNING_INTERVAL_NANOS)) {
            LOG.warn("Rejected {} with HTTP 400, so the handler did not receive them: {}. Further rejections within a minute are logged at DEBUG "
                + "by the logger {}.", batch, reason, LOG.getName());
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("Rejected {} with HTTP 400: {}.", batch, reason);
        }
        return exception;
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
        if (outOfRange(body.lineNumber()) || outOfRange(body.columnNumber())) {
            throw new CodecException("A Content Security Policy violation report requires line and column numbers between 0 and " + MAX_POSITION);
        }
    }

    private static void validate(ContentSecurityPolicyHashReportBody body) {
        requireLength("documentURL", body.documentUrl(), MAX_URL_LENGTH);
        requireLength("subresourceURL", body.subresourceUrl(), MAX_URL_LENGTH);
        requireText("hash", body.hash(), MAX_TOKEN_LENGTH);
        requireLength("destination", body.destination(), MAX_TOKEN_LENGTH);
        requireLength("type", body.type(), MAX_TOKEN_LENGTH);
    }

    private static boolean outOfRange(@Nullable Long position) {
        return position != null && (position < 0 || position > MAX_POSITION);
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

    /**
     * The Reporting API envelope as delivered; its body is decoded once its type is known. It is
     * package-private rather than private so that the generated serde introspection can access it.
     *
     * @param age the report age in milliseconds
     * @param type the report type
     * @param url the URL of the document that generated the report
     * @param userAgent the user agent that generated the report
     * @param body the type-specific report body
     */
    @Serdeable
    record SerializedContentSecurityPolicyReport(
        @Nullable Long age,
        @Nullable String type,
        @Nullable String url,
        @JsonProperty("user_agent") @Nullable String userAgent,
        @Nullable JsonNode body
    ) {
    }

    /**
     * Signals that a body exceeds {@link #MAX_BODY_BYTES}.
     */
    private static final class BodyTooLargeException extends IOException {
        BodyTooLargeException() {
            super(BODY_TOO_LARGE);
        }
    }

    /**
     * Fails once more than {@link #MAX_BODY_BYTES} bytes are read, also when the request declares
     * no {@code Content-Length}.
     */
    static final class BoundedInputStream extends FilterInputStream {
        private long remaining = MAX_BODY_BYTES;

        BoundedInputStream(InputStream in) {
            super(in);
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b != -1) {
                consume(1);
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int read = super.read(b, off, len);
            if (read > 0) {
                consume(read);
            }
            return read;
        }

        private void consume(int bytes) throws BodyTooLargeException {
            remaining -= bytes;
            if (remaining < 0) {
                throw new BodyTooLargeException();
            }
        }
    }
}

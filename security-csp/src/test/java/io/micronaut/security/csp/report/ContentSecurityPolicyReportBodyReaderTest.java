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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpHeaders;
import io.micronaut.http.codec.CodecException;
import io.micronaut.json.JsonMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import static io.micronaut.security.csp.report.ContentSecurityPolicyReportBodyReader.MAX_POLICY_LENGTH;
import static io.micronaut.security.csp.report.ContentSecurityPolicyReportBodyReader.MAX_REPORTS;
import static io.micronaut.security.csp.report.ContentSecurityPolicyReportBodyReader.MAX_SAMPLE_LENGTH;
import static io.micronaut.security.csp.report.ContentSecurityPolicyReportBodyReader.MAX_TOKEN_LENGTH;
import static io.micronaut.security.csp.report.ContentSecurityPolicyReportBodyReader.MAX_URL_LENGTH;
import static io.micronaut.security.csp.report.ContentSecurityPolicyReportBodyReader.MAX_USER_AGENT_LENGTH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the checks the reader always applies, independently of bean validation, which needs
 * micronaut-validation at runtime. Each rejection is pinned to the rule that rejects it by the
 * message, and each limit is tested on both sides of its boundary.
 */
class ContentSecurityPolicyReportBodyReaderTest {
    private static final String VIOLATION = ContentSecurityPolicyReport.TYPE_CSP_VIOLATION;
    private static final String HASH = ContentSecurityPolicyReport.TYPE_CSP_HASH;
    private static ApplicationContext context;
    private static ContentSecurityPolicyReportBodyReader reader;

    @BeforeAll
    static void setUp() {
        context = ApplicationContext.run();
        reader = new ContentSecurityPolicyReportBodyReader(context.getBean(JsonMapper.class));
    }

    @AfterAll
    static void tearDown() {
        context.close();
    }

    @Test
    void decodesTheEnvelopeAndTheViolationBody() {
        List<ContentSecurityPolicyReport> reports = read(batch(envelope(VIOLATION, violationBody(Map.of(
            "blockedURL", text("inline"),
            "sample", text("alert(1)"),
            "lineNumber", "12")))));

        assertEquals(1, reports.size());
        ContentSecurityPolicyReport report = reports.get(0);
        assertEquals(1L, report.age());
        assertEquals(VIOLATION, report.type());
        assertEquals("https://example.com/page", report.url());
        assertEquals("Example Browser", report.userAgent());
        ContentSecurityPolicyViolationReportBody body = assertInstanceOf(ContentSecurityPolicyViolationReportBody.class, report.body());
        assertEquals("https://example.com/page", body.documentUrl());
        assertEquals("inline", body.blockedUrl());
        assertEquals("script-src-elem", body.effectiveDirective());
        assertEquals("script-src 'none'", body.originalPolicy());
        assertEquals(ContentSecurityPolicyReportDisposition.ENFORCE, body.disposition());
        assertEquals(200, body.statusCode());
        assertEquals("alert(1)", body.sample());
        assertEquals(12L, body.lineNumber());
    }

    @Test
    void decodesAHashBody() {
        List<ContentSecurityPolicyReport> reports = read(batch(envelope(HASH, hashBody(Map.of("destination", text("script"))))));

        ContentSecurityPolicyHashReportBody body = assertInstanceOf(ContentSecurityPolicyHashReportBody.class, reports.get(0).body());
        assertEquals("sha256-abc", body.hash());
        assertEquals("script", body.destination());
    }

    @Test
    void skipsReportsOfOtherTypes() {
        List<ContentSecurityPolicyReport> reports = read(batch(envelope("deprecation", "{\"id\":\"x\"}"), envelope(HASH, hashBody(Map.of()))));

        assertEquals(1, reports.size());
        assertEquals(HASH, reports.get(0).type());
    }

    @Test
    void returnsNoReportsForAJsonNullBody() {
        assertNull(read("null"));
    }

    @Test
    void logsASkippedReportTypeOnlyAtDebug() {
        String json = batch(envelope("deprecation", "{\"id\":\"x\"}"));

        List<ILoggingEvent> events = captureAt(Level.DEBUG, () -> assertEquals(List.of(), read(json)));
        assertEquals(1, events.size());
        assertMentions(events.get(0), "not a Content Security Policy report type");
        assertEquals(List.of(), captureAt(Level.INFO, () -> assertEquals(List.of(), read(json))));
    }

    @Test
    void doesNotLogARejectionWithinTheMinuteWhenDebugIsOff() {
        ContentSecurityPolicyReportBodyReader clockedReader = new ContentSecurityPolicyReportBodyReader(context.getBean(JsonMapper.class), () -> 0L);

        List<ILoggingEvent> events = captureAt(Level.INFO, () -> {
            assertThrows(CodecException.class, () -> read(clockedReader, "not json"));
            assertThrows(CodecException.class, () -> read(clockedReader, "not json"));
        });

        assertEquals(List.of(Level.WARN), events.stream().map(ILoggingEvent::getLevel).toList());
    }

    @Test
    void acceptsTheMaximumNumberOfReports() {
        assertEquals(MAX_REPORTS, read(hashBatch(MAX_REPORTS)).size());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("reportsAtTheLimits")
    void acceptsValuesAtTheLimits(String description, String json) {
        assertEquals(1, read(json).size());
    }

    static Stream<Arguments> reportsAtTheLimits() {
        return Stream.of(
            Arguments.of("statusCode 0", batch(envelope(VIOLATION, violationBody(Map.of("statusCode", "0"))))),
            Arguments.of("statusCode 65535", batch(envelope(VIOLATION, violationBody(Map.of("statusCode", "65535"))))),
            Arguments.of("lineNumber and columnNumber 0", batch(envelope(VIOLATION, violationBody(Map.of("lineNumber", "0", "columnNumber", "0"))))),
            Arguments.of("lineNumber and columnNumber 4294967295",
                batch(envelope(VIOLATION, violationBody(Map.of("lineNumber", "4294967295", "columnNumber", "4294967295"))))),
            Arguments.of("age 0", batch(envelope(Map.of("age", "0"), VIOLATION, violationBody(Map.of())))),
            Arguments.of("url of " + MAX_URL_LENGTH + " characters", batch(envelope(Map.of("url", text(MAX_URL_LENGTH)), VIOLATION, violationBody(Map.of())))),
            Arguments.of("user_agent of " + MAX_USER_AGENT_LENGTH + " characters",
                batch(envelope(Map.of("user_agent", text(MAX_USER_AGENT_LENGTH)), VIOLATION, violationBody(Map.of())))),
            Arguments.of("documentURL of " + MAX_URL_LENGTH + " characters", batch(envelope(VIOLATION, violationBody(Map.of("documentURL", text(MAX_URL_LENGTH)))))),
            Arguments.of("effectiveDirective of " + MAX_TOKEN_LENGTH + " characters",
                batch(envelope(VIOLATION, violationBody(Map.of("effectiveDirective", text(MAX_TOKEN_LENGTH)))))),
            Arguments.of("originalPolicy of " + MAX_POLICY_LENGTH + " characters",
                batch(envelope(VIOLATION, violationBody(Map.of("originalPolicy", text(MAX_POLICY_LENGTH)))))),
            Arguments.of("sample of " + MAX_SAMPLE_LENGTH + " characters", batch(envelope(VIOLATION, violationBody(Map.of("sample", text(MAX_SAMPLE_LENGTH)))))),
            Arguments.of("hash of " + MAX_TOKEN_LENGTH + " characters", batch(envelope(HASH, hashBody(Map.of("hash", text(MAX_TOKEN_LENGTH))))))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rejectedReports")
    void rejectsAReportThatBreaksARule(String expectedMessage, String json) {
        CodecException exception = assertThrows(CodecException.class, () -> read(json));

        assertEquals(expectedMessage, exception.getMessage());
    }

    static Stream<Arguments> rejectedReports() {
        return Stream.of(
            Arguments.of("A Reporting API batch must not contain more than " + MAX_REPORTS + " reports", hashBatch(MAX_REPORTS + 1)),
            Arguments.of("A Content Security Policy report batch must not contain null reports", "[null]"),
            Arguments.of("A Content Security Policy report type is required", batch(envelope(Map.of(), null, hashBody(Map.of())))),
            Arguments.of("A Content Security Policy report body is required", batch(envelope(VIOLATION, null))),
            Arguments.of("A Content Security Policy report body is required", batch(envelope(VIOLATION, "null"))),
            Arguments.of("A Content Security Policy report requires a non-negative age", batch(envelope(Map.of("age", "-1"), VIOLATION, violationBody(Map.of())))),
            Arguments.of("A Content Security Policy report requires a non-negative age", batch(envelope(withoutField("age"), VIOLATION, violationBody(Map.of())))),
            Arguments.of(requires("url"), batch(envelope(withoutField("url"), VIOLATION, violationBody(Map.of())))),
            Arguments.of("A Content Security Policy report requires a user_agent", batch(envelope(withoutField("user_agent"), VIOLATION, violationBody(Map.of())))),
            Arguments.of(requires("documentURL"), batch(envelope(VIOLATION, violationBody(withoutField("documentURL"))))),
            Arguments.of(requires("documentURL"), batch(envelope(VIOLATION, "{}"))),
            Arguments.of(requires("effectiveDirective"), batch(envelope(VIOLATION, violationBody(withoutField("effectiveDirective"))))),
            Arguments.of(requires("originalPolicy"), batch(envelope(VIOLATION, violationBody(withoutField("originalPolicy"))))),
            Arguments.of("A Content Security Policy violation report requires a disposition", batch(envelope(VIOLATION, violationBody(withoutField("disposition"))))),
            Arguments.of(invalidStatusCode(), batch(envelope(VIOLATION, violationBody(withoutField("statusCode"))))),
            Arguments.of(invalidStatusCode(), batch(envelope(VIOLATION, violationBody(Map.of("statusCode", "-1"))))),
            Arguments.of(invalidStatusCode(), batch(envelope(VIOLATION, violationBody(Map.of("statusCode", "65536"))))),
            Arguments.of(positionOutOfRange(), batch(envelope(VIOLATION, violationBody(Map.of("lineNumber", "-1"))))),
            Arguments.of(positionOutOfRange(), batch(envelope(VIOLATION, violationBody(Map.of("columnNumber", "-1"))))),
            Arguments.of(positionOutOfRange(), batch(envelope(VIOLATION, violationBody(Map.of("lineNumber", "4294967296"))))),
            Arguments.of(positionOutOfRange(), batch(envelope(VIOLATION, violationBody(Map.of("columnNumber", "9223372036854775807"))))),
            Arguments.of(requires("hash"), batch(envelope(HASH, hashBody(Map.of("hash", text(" ")))))),
            Arguments.of(tooLong("url", MAX_URL_LENGTH), batch(envelope(Map.of("url", text(MAX_URL_LENGTH + 1)), VIOLATION, violationBody(Map.of())))),
            Arguments.of(tooLong("user_agent", MAX_USER_AGENT_LENGTH),
                batch(envelope(Map.of("user_agent", text(MAX_USER_AGENT_LENGTH + 1)), VIOLATION, violationBody(Map.of())))),
            Arguments.of(tooLong("documentURL", MAX_URL_LENGTH), batch(envelope(VIOLATION, violationBody(Map.of("documentURL", text(MAX_URL_LENGTH + 1)))))),
            Arguments.of(tooLong("referrer", MAX_URL_LENGTH), batch(envelope(VIOLATION, violationBody(Map.of("referrer", text(MAX_URL_LENGTH + 1)))))),
            Arguments.of(tooLong("blockedURL", MAX_URL_LENGTH), batch(envelope(VIOLATION, violationBody(Map.of("blockedURL", text(MAX_URL_LENGTH + 1)))))),
            Arguments.of(tooLong("effectiveDirective", MAX_TOKEN_LENGTH),
                batch(envelope(VIOLATION, violationBody(Map.of("effectiveDirective", text(MAX_TOKEN_LENGTH + 1)))))),
            Arguments.of(tooLong("originalPolicy", MAX_POLICY_LENGTH),
                batch(envelope(VIOLATION, violationBody(Map.of("originalPolicy", text(MAX_POLICY_LENGTH + 1)))))),
            Arguments.of(tooLong("sourceFile", MAX_URL_LENGTH), batch(envelope(VIOLATION, violationBody(Map.of("sourceFile", text(MAX_URL_LENGTH + 1)))))),
            Arguments.of(tooLong("sample", MAX_SAMPLE_LENGTH), batch(envelope(VIOLATION, violationBody(Map.of("sample", text(MAX_SAMPLE_LENGTH + 1)))))),
            Arguments.of(tooLong("documentURL", MAX_URL_LENGTH), batch(envelope(HASH, hashBody(Map.of("documentURL", text(MAX_URL_LENGTH + 1)))))),
            Arguments.of(tooLong("subresourceURL", MAX_URL_LENGTH), batch(envelope(HASH, hashBody(Map.of("subresourceURL", text(MAX_URL_LENGTH + 1)))))),
            Arguments.of(tooLong("hash", MAX_TOKEN_LENGTH), batch(envelope(HASH, hashBody(Map.of("hash", text(MAX_TOKEN_LENGTH + 1)))))),
            Arguments.of(tooLong("destination", MAX_TOKEN_LENGTH), batch(envelope(HASH, hashBody(Map.of("destination", text(MAX_TOKEN_LENGTH + 1)))))),
            Arguments.of(tooLong("type", MAX_TOKEN_LENGTH), batch(envelope(HASH, hashBody(Map.of("type", text(MAX_TOKEN_LENGTH + 1))))))
        );
    }

    @Test
    void rejectsABodyThatIsNotJson() {
        CodecException exception = assertThrows(CodecException.class, () -> read("not json"));

        assertEquals("The body is not a valid Reporting API batch", exception.getMessage(), "the decoder's message names internal types");
        assertNotNull(exception.getCause());
    }

    @Test
    void rejectsABodyDeclaredLargerThanTheLimitBeforeReadingIt() {
        MutableHttpHeaders headers = HttpResponse.ok().getHeaders();
        headers.add(HttpHeaders.CONTENT_LENGTH, String.valueOf(ContentSecurityPolicyReportBodyReader.MAX_BODY_BYTES + 1));
        InputStream unreadable = new InputStream() {
            @Override
            public int read() {
                throw new AssertionError("the body must not be read");
            }
        };

        CodecException exception = assertThrows(CodecException.class, () -> read(reader, headers, unreadable));

        assertEquals(bodyTooLarge(), exception.getMessage());
    }

    @Test
    void rejectsALargerBodyWithoutContentLengthOnceTheLimitIsRead() {
        String padding = " ".repeat(ContentSecurityPolicyReportBodyReader.MAX_BODY_BYTES);

        CodecException exception = assertThrows(CodecException.class, () -> read("[" + padding + envelope(HASH, hashBody(Map.of())) + "]"));

        assertEquals(bodyTooLarge(), exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"not a number", "512"})
    void readsABodyWhoseDeclaredLengthIsWithinTheLimitOrInvalid(String contentLength) {
        MutableHttpHeaders headers = HttpResponse.ok().getHeaders();
        headers.add(HttpHeaders.CONTENT_LENGTH, contentLength);
        String json = batch(envelope(HASH, hashBody(Map.of())));

        assertEquals(1, read(reader, headers, new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8))).size());
    }

    @Test
    void boundedStreamCountsSingleByteReads() throws IOException {
        byte[] body = new byte[ContentSecurityPolicyReportBodyReader.MAX_BODY_BYTES + 1];
        try (InputStream stream = new ContentSecurityPolicyReportBodyReader.BoundedInputStream(new ByteArrayInputStream(body))) {
            for (int i = 0; i < ContentSecurityPolicyReportBodyReader.MAX_BODY_BYTES; i++) {
                assertEquals(0, stream.read());
            }
            IOException exception = assertThrows(IOException.class, stream::read);
            assertEquals(bodyTooLarge(), exception.getMessage());
        }
        try (InputStream stream = new ContentSecurityPolicyReportBodyReader.BoundedInputStream(new ByteArrayInputStream(new byte[0]))) {
            assertEquals(-1, stream.read());
            assertEquals(-1, stream.read(new byte[8], 0, 8));
        }
    }

    @Test
    void logsRejectedBatchesAtWarnOncePerMinuteWithoutTheReportContents() {
        AtomicLong now = new AtomicLong(1_000L);
        ContentSecurityPolicyReportBodyReader clockedReader = new ContentSecurityPolicyReportBodyReader(context.getBean(JsonMapper.class), now::get);
        String oversized = batch(envelope(VIOLATION, violationBody(Map.of(
            "documentURL", text(MAX_URL_LENGTH + 1),
            "sample", text("secret sample")))));

        List<ILoggingEvent> events = captureDebug(() -> {
            assertThrows(CodecException.class, () -> read(clockedReader, oversized));
            assertThrows(CodecException.class, () -> read(clockedReader, "not json"));
            assertThrows(CodecException.class, () -> read(clockedReader, batch(envelope(HASH, "[]"))));
            now.addAndGet(TimeUnit.MINUTES.toNanos(1) - 1);
            assertThrows(CodecException.class, () -> read(clockedReader, oversized));
            now.addAndGet(1);
            assertThrows(CodecException.class, () -> read(clockedReader, oversized));
        });

        assertEquals(List.of(Level.WARN, Level.DEBUG, Level.DEBUG, Level.DEBUG, Level.WARN), events.stream().map(ILoggingEvent::getLevel).toList(),
            "the first rejection of each minute is logged at WARN and the others at DEBUG");
        assertMentions(events.get(0), "batch of 1 Content Security Policy reports", "HTTP 400", tooLong("documentURL", MAX_URL_LENGTH),
            ContentSecurityPolicyReportBodyReader.class.getName());
        assertMentions(events.get(1), "the body is not a JSON array of Reporting API reports");
        assertMentions(events.get(2), "batch of 1 Content Security Policy reports", "a report body could not be decoded");
        assertTrue(events.stream().noneMatch(event -> event.getFormattedMessage().contains("secret sample")), "report contents must not be logged");
    }

    private static String bodyTooLarge() {
        return "A Reporting API batch must not be larger than " + ContentSecurityPolicyReportBodyReader.MAX_BODY_BYTES + " bytes";
    }

    private static String requires(String field) {
        return "A Content Security Policy report requires " + field;
    }

    private static String tooLong(String field, int maxLength) {
        return "A Content Security Policy report field " + field + " must not be longer than " + maxLength + " characters";
    }

    private static String invalidStatusCode() {
        return "A Content Security Policy violation report requires a valid statusCode";
    }

    private static String positionOutOfRange() {
        return "A Content Security Policy violation report requires line and column numbers between 0 and 4294967295";
    }

    /**
     * Marks a field to leave out of {@link #object(Map, Map)}.
     */
    private static Map<String, String> withoutField(String field) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put(field, null);
        return fields;
    }

    private static String text(String value) {
        return "\"" + value + "\"";
    }

    private static String text(int length) {
        return text("x".repeat(length));
    }

    private static String violationBody(Map<String, String> overrides) {
        Map<String, String> defaults = new LinkedHashMap<>();
        defaults.put("documentURL", text("https://example.com/page"));
        defaults.put("effectiveDirective", text("script-src-elem"));
        defaults.put("originalPolicy", text("script-src 'none'"));
        defaults.put("disposition", text("enforce"));
        defaults.put("statusCode", "200");
        return object(defaults, overrides);
    }

    private static String hashBody(Map<String, String> overrides) {
        Map<String, String> defaults = new LinkedHashMap<>();
        defaults.put("hash", text("sha256-abc"));
        return object(defaults, overrides);
    }

    private static String envelope(String type, String body) {
        return envelope(Map.of(), type, body);
    }

    private static String envelope(Map<String, String> overrides, String type, String body) {
        Map<String, String> defaults = new LinkedHashMap<>();
        defaults.put("type", type == null ? null : text(type));
        defaults.put("age", "1");
        defaults.put("url", text("https://example.com/page"));
        defaults.put("user_agent", text("Example Browser"));
        defaults.put("body", body);
        return object(defaults, overrides);
    }

    /**
     * Builds a JSON object from raw JSON values. An override replaces a default; a {@code null}
     * value leaves the field out.
     */
    private static String object(Map<String, String> defaults, Map<String, String> overrides) {
        Map<String, String> fields = new LinkedHashMap<>(defaults);
        fields.putAll(overrides);
        StringJoiner joiner = new StringJoiner(",", "{", "}");
        fields.forEach((name, value) -> {
            if (value != null) {
                joiner.add(text(name) + ":" + value);
            }
        });
        return joiner.toString();
    }

    private static String batch(String... reports) {
        StringJoiner joiner = new StringJoiner(",", "[", "]");
        for (String report : reports) {
            joiner.add(report);
        }
        return joiner.toString();
    }

    private static String hashBatch(int size) {
        String[] reports = new String[size];
        for (int i = 0; i < size; i++) {
            reports[i] = envelope(HASH, hashBody(Map.of()));
        }
        return batch(reports);
    }

    private static List<ILoggingEvent> captureDebug(Runnable action) {
        return captureAt(Level.DEBUG, action);
    }

    private static List<ILoggingEvent> captureAt(Level captureLevel, Runnable action) {
        Logger logger = (Logger) LoggerFactory.getLogger(ContentSecurityPolicyReportBodyReader.class);
        Level level = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(captureLevel);
        try {
            action.run();
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(level);
        }
        return appender.list;
    }

    private static void assertMentions(ILoggingEvent event, String... facts) {
        String message = event.getFormattedMessage();
        for (String fact : facts) {
            assertTrue(message.contains(fact), () -> "expected \"" + fact + "\" in: " + message);
        }
    }

    private static List<ContentSecurityPolicyReport> read(String json) {
        return read(reader, json);
    }

    private static List<ContentSecurityPolicyReport> read(ContentSecurityPolicyReportBodyReader reader, String json) {
        return read(reader, HttpResponse.ok().getHeaders(), new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
    }

    private static List<ContentSecurityPolicyReport> read(ContentSecurityPolicyReportBodyReader reader, MutableHttpHeaders headers, InputStream body) {
        return reader.read(Argument.listOf(ContentSecurityPolicyReport.class), MediaType.of(ContentSecurityPolicyController.APPLICATION_REPORTS_JSON),
            headers, body);
    }
}

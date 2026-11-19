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

import io.micronaut.context.ApplicationContext;
import io.micronaut.core.type.Argument;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.codec.CodecException;
import io.micronaut.json.JsonMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.StringJoiner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Exercises the checks the reader always applies, independently of bean validation, which needs
 * micronaut-validation at runtime.
 */
class ContentSecurityPolicyReportBodyReaderTest {
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
    void acceptsAValidViolationReport() {
        List<ContentSecurityPolicyReport> reports = read("[" + violation("\"https://example.com/page\"", "200", "\"alert(1)\"") + "]");

        assertEquals(1, reports.size());
    }

    @Test
    void acceptsTheMaximumNumberOfReports() {
        assertEquals(ContentSecurityPolicyReportBodyReader.MAX_REPORTS, read(batch(ContentSecurityPolicyReportBodyReader.MAX_REPORTS)).size());
    }

    @Test
    void rejectsMoreReportsThanTheMaximum() {
        assertThrows(CodecException.class, () -> read(batch(ContentSecurityPolicyReportBodyReader.MAX_REPORTS + 1)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        // missing documentURL
        "[{\"type\":\"csp-violation\",\"age\":1,\"url\":\"https://e.com\",\"user_agent\":\"UA\",\"body\":{\"effectiveDirective\":\"script-src\",\"originalPolicy\":\"script-src 'none'\",\"disposition\":\"enforce\",\"statusCode\":200}}]",
        // missing effectiveDirective, originalPolicy, disposition and statusCode
        "[{\"type\":\"csp-violation\",\"age\":1,\"url\":\"https://e.com\",\"user_agent\":\"UA\",\"body\":{\"documentURL\":\"https://e.com\"}}]",
        // empty body
        "[{\"type\":\"csp-violation\",\"age\":1,\"url\":\"https://e.com\",\"user_agent\":\"UA\",\"body\":{}}]",
        // missing envelope url, age and user_agent
        "[{\"type\":\"csp-hash\",\"body\":{\"hash\":\"sha256-x\"}}]",
        // negative age
        "[{\"type\":\"csp-hash\",\"age\":-1,\"url\":\"https://e.com\",\"user_agent\":\"UA\",\"body\":{\"hash\":\"sha256-x\"}}]",
        // blank hash
        "[{\"type\":\"csp-hash\",\"age\":1,\"url\":\"https://e.com\",\"user_agent\":\"UA\",\"body\":{\"hash\":\" \"}}]"
    })
    void rejectsReportsMissingRequiredFields(String json) {
        assertThrows(CodecException.class, () -> read(json));
    }

    @Test
    void rejectsAnOversizedField() {
        String longSample = "\"" + "x".repeat(ContentSecurityPolicyReportBodyReader.MAX_SAMPLE_LENGTH + 1) + "\"";

        assertThrows(CodecException.class, () -> read("[" + violation("\"https://example.com/page\"", "200", longSample) + "]"));
    }

    @Test
    void rejectsAnOversizedUrl() {
        String longUrl = "\"https://example.com/" + "x".repeat(ContentSecurityPolicyReportBodyReader.MAX_URL_LENGTH) + "\"";

        assertThrows(CodecException.class, () -> read("[" + violation(longUrl, "200", "null") + "]"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"-1", "65536"})
    void rejectsAnInvalidStatusCode(String statusCode) {
        assertThrows(CodecException.class, () -> read("[" + violation("\"https://example.com/page\"", statusCode, "null") + "]"));
    }

    @Test
    void rejectsNegativeLineNumbers() {
        String json = "[{\"type\":\"csp-violation\",\"age\":1,\"url\":\"https://e.com\",\"user_agent\":\"UA\",\"body\":{"
            + "\"documentURL\":\"https://e.com\",\"effectiveDirective\":\"script-src\",\"originalPolicy\":\"script-src 'none'\","
            + "\"disposition\":\"enforce\",\"statusCode\":200,\"lineNumber\":-1}}]";

        assertThrows(CodecException.class, () -> read(json));
    }

    private static String violation(String documentUrl, String statusCode, String sample) {
        return "{\"type\":\"csp-violation\",\"age\":1,\"url\":\"https://example.com/page\",\"user_agent\":\"Example Browser\",\"body\":{"
            + "\"documentURL\":" + documentUrl + ",\"effectiveDirective\":\"script-src\",\"originalPolicy\":\"script-src 'none'\","
            + "\"disposition\":\"enforce\",\"statusCode\":" + statusCode + ",\"sample\":" + sample + "}}";
    }

    private static String batch(int size) {
        StringJoiner joiner = new StringJoiner(",", "[", "]");
        for (int i = 0; i < size; i++) {
            joiner.add("{\"type\":\"csp-hash\",\"age\":1,\"url\":\"https://e.com\",\"user_agent\":\"UA\",\"body\":{\"hash\":\"sha256-x\"}}");
        }
        return joiner.toString();
    }

    private static List<ContentSecurityPolicyReport> read(String json) {
        MutableHttpHeaders headers = HttpResponse.ok().getHeaders();
        return reader.read(Argument.listOf(ContentSecurityPolicyReport.class), MediaType.of(ContentSecurityPolicyController.APPLICATION_REPORTS_JSON),
            headers, new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
    }
}

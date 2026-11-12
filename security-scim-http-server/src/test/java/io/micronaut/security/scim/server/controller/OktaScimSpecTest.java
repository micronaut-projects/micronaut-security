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
package io.micronaut.security.scim.server.controller;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Runs the HTTP requests and declarative assertions from Okta's SCIM 2.0 Runscope specification test.
 *
 * @see <a href="https://developer.okta.com/standards/SCIM/SCIMFiles/Okta-SCIM-20-SPEC-Test.json">
 * Okta SCIM 2.0 SPEC Test</a>
 */
@MicronautTest(transactional = false)
@Property(name = "spec.name", value = "OktaScimSpecTest")
@Property(name = "datasources.default.url",
    value = "jdbc:h2:mem:okta-scim-spec-test;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE;DATABASE_TO_UPPER=false")
@Property(name = "datasources.default.driver-class-name", value = "org.h2.Driver")
@Property(name = "datasources.default.username", value = "sa")
@Property(name = "datasources.default.password", value = "")
@Property(name = "datasources.default.dialect", value = "H2")
@Property(name = "datasources.default.schema-generate", value = "CREATE_DROP")
@Property(name = "micronaut.security.scim.data.dialect", value = "H2")
class OktaScimSpecTest {
    private static final String SPEC_RESOURCE = "/Okta-SCIM-20-SPEC-Test.json";
    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);
    private static final Pattern VARIABLE_PATTERN = Pattern.compile("\\{\\{([^}]+)}}");

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void passesOktaScim20SpecTest() throws IOException {
        BlockingHttpClient client = httpClient.toBlocking();
        createRequiredInitialUser(client);

        Map<String, Object> specification = loadSpecification();
        assertEquals("Okta SCIM 2.0 SPEC Test", specification.get("name"));
        Map<String, String> variables = initialVariables();
        int requestsExecuted = 0;
        for (Map<String, Object> step : maps(specification.get("steps"))) {
            if (Boolean.TRUE.equals(step.get("skipped"))) {
                continue;
            }
            String stepType = String.valueOf(step.get("step_type"));
            if ("pause".equals(stepType)) {
                continue;
            }
            if (!"request".equals(stepType)) {
                fail("Unsupported Okta specification step type " + stepType);
            }
            executeStep(client, step, variables);
            requestsExecuted++;
        }
        assertEquals(12, requestsExecuted, "Every HTTP request in the checked-in Okta specification must run");
    }

    private void createRequiredInitialUser(BlockingHttpClient client) {
        String body = """
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
              "userName": "existing.okta.user@example.test",
              "name": {"givenName": "Existing", "familyName": "User"},
              "emails": [{"primary": true, "value": "existing.okta.user@example.test", "type": "work"}],
              "active": true
            }
            """;
        HttpResponse<?> response = client.exchange(HttpRequest.POST("/scim/v2/Users", body)
            .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
            .accept(ScimMediaType.APPLICATION_SCIM_JSON_TYPE));
        assertEquals(HttpStatus.CREATED, response.getStatus());
    }

    private Map<String, Object> loadSpecification() throws IOException {
        try (InputStream input = OktaScimSpecTest.class.getResourceAsStream(SPEC_RESOURCE)) {
            assertNotNull(input, "Missing Okta SCIM specification test resource");
            return jsonMapper.readValue(input.readAllBytes(), MAP_ARGUMENT);
        }
    }

    private void executeStep(
        BlockingHttpClient client,
        Map<String, Object> step,
        Map<String, String> variables
    ) throws IOException {
        String note = String.valueOf(step.get("note"));
        MutableHttpRequest<?> request = request(step, variables);
        long started = System.nanoTime();
        HttpResponse<?> response;
        try {
            response = client.exchange(request, String.class);
        } catch (HttpClientResponseException e) {
            response = e.getResponse();
        }
        long responseTimeMillis = (System.nanoTime() - started) / 1_000_000;
        String responseBody = response.getBody(String.class).orElse("");
        Object responseJson = responseBody.isBlank() ? null : jsonMapper.readValue(responseBody, Object.class);

        for (Map<String, Object> assertion : maps(step.get("assertions"))) {
            verifyAssertion(note, assertion, response, responseJson, responseTimeMillis, variables);
        }
        for (Map<String, Object> variable : maps(step.get("variables"))) {
            if (!"response_json".equals(variable.get("source"))) {
                fail(note + ": unsupported variable source " + variable.get("source"));
            }
            Object value = property(responseJson, String.valueOf(variable.get("property")));
            assertNotNull(value, note + ": variable " + variable.get("name") + " was null");
            variables.put(String.valueOf(variable.get("name")), String.valueOf(value));
        }
    }

    private static MutableHttpRequest<?> request(Map<String, Object> step, Map<String, String> variables) {
        String method = String.valueOf(step.get("method"));
        String uri = encodeUri(substitute(String.valueOf(step.get("url")), variables));
        MutableHttpRequest<?> request = switch (method) {
            case "GET" -> HttpRequest.GET(uri);
            case "POST" -> HttpRequest.POST(uri, substitute(String.valueOf(step.get("body")), variables));
            default -> throw new AssertionError("Unsupported Okta specification HTTP method: " + method);
        };
        Object headers = step.get("headers");
        if (headers instanceof Map<?, ?> headerMap) {
            headerMap.forEach((name, values) -> {
                if (values instanceof Collection<?> collection) {
                    collection.forEach(value -> request.header(
                        String.valueOf(name), substitute(String.valueOf(value), variables)));
                }
            });
        }
        return request;
    }

    private static void verifyAssertion(
        String note,
        Map<String, Object> assertion,
        HttpResponse<?> response,
        @Nullable Object responseJson,
        long responseTimeMillis,
        Map<String, String> variables
    ) {
        String comparison = String.valueOf(assertion.get("comparison"));
        String source = String.valueOf(assertion.get("source"));
        String property = assertion.get("property") == null ? null : String.valueOf(assertion.get("property"));
        String expected = assertion.get("value") == null
            ? null
            : substitute(String.valueOf(assertion.get("value")), variables);
        Object actual = switch (source) {
            case "response_status" -> response.code();
            case "response_json" -> property(responseJson, property);
            case "response_time" -> responseTimeMillis;
            default -> throw new AssertionError(note + ": unsupported assertion source " + source);
        };
        String message = note + (property == null ? "" : ", property " + property);

        switch (comparison) {
            case "equal" -> assertEquals(expected, String.valueOf(actual), message);
            case "equal_number" -> assertNumberEquals(expected, actual, message);
            case "not_empty" -> assertFalse(isEmpty(actual), message);
            case "has_value", "contains" -> assertContains(actual, expected, message);
            case "is_a_number" -> assertTrue(actual instanceof Number, message);
            case "is_less_than" -> assertTrue(number(actual).compareTo(number(expected)) < 0,
                message + ": expected less than " + expected + " but was " + actual);
            default -> throw new AssertionError(note + ": unsupported Okta comparison " + comparison);
        }
    }

    private static void assertNumberEquals(@Nullable String expected, @Nullable Object actual, String message) {
        assertEquals(0, number(expected).compareTo(number(actual)), message);
    }

    private static void assertContains(@Nullable Object actual, @Nullable String expected, String message) {
        if (actual instanceof Collection<?> values) {
            assertTrue(values.stream().anyMatch(value -> String.valueOf(value).equals(expected)), message);
        } else {
            assertTrue(String.valueOf(actual).contains(String.valueOf(expected)), message);
        }
    }

    private static boolean isEmpty(@Nullable Object value) {
        return value == null
            || value instanceof CharSequence chars && chars.isEmpty()
            || value instanceof Collection<?> collection && collection.isEmpty()
            || value instanceof Map<?, ?> map && map.isEmpty();
    }

    private static BigDecimal number(@Nullable Object value) {
        assertNotNull(value);
        return new BigDecimal(String.valueOf(value));
    }

    @Nullable
    private static Object property(@Nullable Object document, @Nullable String path) {
        if (path == null) {
            return document;
        }
        Object current = document;
        for (String segment : path.split("\\.")) {
            int bracket = segment.indexOf('[');
            String key = bracket < 0 ? segment : segment.substring(0, bracket);
            if (!key.isEmpty()) {
                if (!(current instanceof Map<?, ?> values)) {
                    return null;
                }
                current = values.get(key);
            }
            while (bracket >= 0) {
                int end = segment.indexOf(']', bracket);
                if (end < 0 || !(current instanceof List<?> values)) {
                    return null;
                }
                int index = Integer.parseInt(segment.substring(bracket + 1, end));
                if (index >= values.size()) {
                    return null;
                }
                current = values.get(index);
                bracket = segment.indexOf('[', end + 1);
            }
        }
        return current;
    }

    private static String substitute(String value, Map<String, String> variables) {
        Matcher matcher = VARIABLE_PATTERN.matcher(value);
        StringBuilder result = new StringBuilder();
        while (matcher.find()) {
            String name = matcher.group(1);
            String replacement = variables.get(name);
            if (replacement == null) {
                throw new AssertionError("No value configured for Okta specification variable " + name);
            }
            matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(result);
        return result.toString();
    }

    private static String encodeUri(String uri) {
        return uri.replace(" ", "%20").replace("\"", "%22");
    }

    private static Map<String, String> initialVariables() {
        Map<String, String> variables = new LinkedHashMap<>();
        variables.put("SCIMBaseURL", "/scim/v2");
        variables.put("auth", "Bearer okta-test-token");
        variables.put("InvalidUserEmail", "invalid.user@example.test");
        variables.put("UserIdThatDoesNotExist", "user-that-does-not-exist");
        variables.put("randomEmail", "okta.spec.user@example.test");
        variables.put("randomUsername", "okta.spec.user@example.test");
        variables.put("randomUsernameCaps", "OKTA.SPEC.USER@EXAMPLE.TEST");
        variables.put("randomGivenName", "Okta");
        variables.put("randomFamilyName", "Spec");
        return variables;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> maps(@Nullable Object value) {
        return value == null ? List.of() : (List<Map<String, Object>>) value;
    }

    @Requires(property = "spec.name", value = "OktaScimSpecTest")
    @ServerFilter("/scim/v2/**")
    static class InvalidOktaTokenFilter {
        @RequestFilter
        @Nullable
        HttpResponse<?> rejectInvalidToken(HttpRequest<?> request) {
            return "non-token".equals(request.getHeaders().get(HttpHeaders.AUTHORIZATION))
                ? HttpResponse.unauthorized()
                : null;
        }
    }
}

/*
 * Copyright 2026 original authors
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
package io.micronaut.security.csrf.filter;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.generator.CsrfTokenGenerator;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A form body which cannot be decoded (for example because of an invalid percent escape) must not make the CSRF filter
 * fail with a 500 response nor make the server log the raw request body. The request is rejected like any other request
 * without a valid CSRF token.
 */
class CsrfFilterMalformedBodyTest {
    private static final String SPEC_NAME = "CsrfFilterMalformedBodyTest";
    private static final String INJECTED_LINE = "INJECTED-LOG-LINE-test-fixture";

    private EmbeddedServer server;
    private HttpClient httpClient;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setup() {
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.redirect.enabled", StringUtils.FALSE,
            "micronaut.security.csrf.signature-key", "test-fixture-not-a-secret-csrf-signature-key"));
        httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        appender = new ListAppender<>();
        appender.start();
        rootLogger().addAppender(appender);
    }

    @AfterEach
    void cleanup() {
        rootLogger().detachAppender(appender);
        appender.stop();
        httpClient.close();
        server.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "amount=1&csrfToken=%zz\r\n" + INJECTED_LINE,
        "amount=1&csrfToken=%\n" + INJECTED_LINE,
        INJECTED_LINE + "=%zz&amount=1"
    })
    void malformedFormBodyIsRejectedWithoutServerErrorAndWithoutLoggingTheBody(String body) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.retrieve(formPost(body)));
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());

        List<ILoggingEvent> events = List.copyOf(appender.list);
        assertFalse(events.stream().anyMatch(event -> event.getLevel().isGreaterOrEqual(Level.ERROR)),
            () -> "unexpected error log: " + events.stream().filter(e -> e.getLevel().isGreaterOrEqual(Level.ERROR)).map(ILoggingEvent::getFormattedMessage).toList());
        assertFalse(events.stream().anyMatch(CsrfFilterMalformedBodyTest::mentionsTheRequestBody),
            () -> "request body leaked into the log: " + events.stream().filter(CsrfFilterMalformedBodyTest::mentionsTheRequestBody).map(ILoggingEvent::getFormattedMessage).toList());
    }

    @Test
    void wellFormedBodyWithValidTokenIsAccepted() {
        BlockingHttpClient client = httpClient.toBlocking();
        CsrfConfiguration csrfConfiguration = server.getApplicationContext().getBean(CsrfConfiguration.class);
        CsrfTokenGenerator<HttpRequest<?>> generator = server.getApplicationContext().getBean(CsrfTokenGenerator.class);
        String csrfToken = generator.generateCsrfToken(formPost("amount=1"));
        HttpRequest<?> request = HttpRequest.POST("/payout", Map.of("amount", "1", csrfConfiguration.getFieldName(), csrfToken))
            .cookie(Cookie.of(csrfConfiguration.getCookieName(), csrfToken))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
            .accept(MediaType.TEXT_PLAIN);
        assertEquals("payout", client.retrieve(request));
    }

    @Test
    void wellFormedBodyWithoutTokenIsRejected() {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.retrieve(formPost("amount=1")));
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
    }

    private static boolean mentionsTheRequestBody(ILoggingEvent event) {
        if (event.getFormattedMessage() != null && event.getFormattedMessage().contains(INJECTED_LINE)) {
            return true;
        }
        IThrowableProxy throwableProxy = event.getThrowableProxy();
        while (throwableProxy != null) {
            if (throwableProxy.getMessage() != null && throwableProxy.getMessage().contains(INJECTED_LINE)) {
                return true;
            }
            throwableProxy = throwableProxy.getCause();
        }
        return false;
    }

    private static Logger rootLogger() {
        return (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    }

    private static HttpRequest<?> formPost(String body) {
        return HttpRequest.POST("/payout", body)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
            .accept(MediaType.TEXT_PLAIN);
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class FormController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/payout")
        String payout(@Body Map<String, String> form) {
            return "payout";
        }
    }
}

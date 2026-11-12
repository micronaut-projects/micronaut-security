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
package io.micronaut.security.filters;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "SecurityFilterAttributeLoggingTest")
@MicronautTest
class SecurityFilterAttributeLoggingTest {

    // Mirrors OauthAuthenticationMapper.ACCESS_TOKEN_KEY / REFRESH_TOKEN_KEY and OpenIdAuthenticationMapper.OPENID_TOKEN_KEY
    private static final String ACCESS_TOKEN = "access-token-secret-value";
    private static final String REFRESH_TOKEN = "refresh-token-secret-value";
    private static final String OPENID_TOKEN = "openid-token-secret-value";
    private static final String CUSTOM_TOKEN = "custom-token-secret-value";
    private static final String EMAIL = "alice@example.com";
    private static final String MESSAGE_PREFIX = "Authentication attributes:";

    @Inject
    @Client("/")
    HttpClient httpClient;

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setup() {
        logger = (Logger) LoggerFactory.getLogger(SecurityFilter.class);
        originalLevel = logger.getLevel();
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void cleanup() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(originalLevel);
    }

    @Test
    void atDebugOnlyTheAuthenticationAttributeKeysAreLoggedNeverTheValues() {
        logger.setLevel(Level.DEBUG);

        String username = httpClient.toBlocking().retrieve(HttpRequest.GET("/attribute-logging"));

        assertEquals("alice", username);

        List<String> messages = loggedMessages();
        String attributesMessage = attributesMessage(messages);
        assertTrue(attributesMessage.contains("accessToken"));
        assertTrue(attributesMessage.contains("refreshToken"));
        assertTrue(attributesMessage.contains("openIdToken"));
        assertTrue(attributesMessage.contains("email"));

        assertNotLogged(messages, ACCESS_TOKEN);
        assertNotLogged(messages, REFRESH_TOKEN);
        assertNotLogged(messages, OPENID_TOKEN);
        assertNotLogged(messages, CUSTOM_TOKEN);
        assertNotLogged(messages, EMAIL);
    }

    @Test
    void atTraceAttributeValuesAreLoggedButTokenValuesAreRedacted() {
        logger.setLevel(Level.TRACE);

        String username = httpClient.toBlocking().retrieve(HttpRequest.GET("/attribute-logging"));

        assertEquals("alice", username);

        List<String> messages = loggedMessages();
        String attributesMessage = attributesMessage(messages);
        assertTrue(attributesMessage.contains("email=>" + EMAIL));

        assertTrue(attributesMessage.contains("accessToken=><redacted>"));
        assertTrue(attributesMessage.contains("refreshToken=><redacted>"));
        assertTrue(attributesMessage.contains("openIdToken=><redacted>"));
        assertTrue(attributesMessage.contains("X-Custom-Token=><redacted>"));
        assertNotLogged(messages, ACCESS_TOKEN);
        assertNotLogged(messages, REFRESH_TOKEN);
        assertNotLogged(messages, OPENID_TOKEN);
        assertNotLogged(messages, CUSTOM_TOKEN);
    }

    private List<String> loggedMessages() {
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    private static String attributesMessage(List<String> messages) {
        return messages.stream()
                .filter(message -> message.startsWith(MESSAGE_PREFIX))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No authentication attributes message was logged"));
    }

    private static void assertNotLogged(List<String> messages, String value) {
        assertTrue(messages.stream().noneMatch(message -> message.contains(value)), () -> value + " was logged");
    }

    @Requires(property = "spec.name", value = "SecurityFilterAttributeLoggingTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/attribute-logging")
    static class AttributeLoggingController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Authentication authentication) {
            return authentication.getName();
        }
    }

    @Requires(property = "spec.name", value = "SecurityFilterAttributeLoggingTest")
    @Singleton
    static class TokenAttributesAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {
        @Override
        public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
            Map<String, Object> attributes = new LinkedHashMap<>();
            attributes.put("accessToken", ACCESS_TOKEN);
            attributes.put("refreshToken", REFRESH_TOKEN);
            attributes.put("openIdToken", OPENID_TOKEN);
            attributes.put("X-Custom-Token", CUSTOM_TOKEN);
            attributes.put("email", EMAIL);
            return Mono.just(Authentication.build("alice", attributes));
        }
    }
}

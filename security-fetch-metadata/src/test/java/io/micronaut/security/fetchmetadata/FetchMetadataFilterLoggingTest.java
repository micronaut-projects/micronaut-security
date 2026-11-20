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
package io.micronaut.security.fetchmetadata;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FetchMetadataFilterLoggingTest {

    private final Logger logger = (Logger) LoggerFactory.getLogger(FetchMetadataFilter.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @BeforeEach
    void attachAppender() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(appender);
    }

    @Test
    void logsWhyNoRuleAllowedTheRequestWithoutCookieValues() {
        FetchMetadataRule<HttpRequest<?>> unknown = request -> FetchMetadataRuleResult.UNKNOWN;

        new FetchMetadataFilter(List.of(unknown)).filterRequest(crossSiteRequestWithCookie());

        ILoggingEvent event = singleEvent();
        assertEquals(Level.DEBUG, event.getLevel());
        String message = event.getFormattedMessage();
        assertTrue(message.contains("POST /account rejected because no Fetch Metadata rule allowed it"), message);
        assertTrue(message.contains("site=cross-site, mode=navigate, dest=document, origin=https://evil.example, cookie=present"), message);
        assertTrue(message.contains("#fetchMetadata"), message);
        assertFalse(message.contains("secret-session-id"), message);
    }

    @Test
    void logsTheRejectingRuleAndAbsentHeaders() {
        FetchMetadataRule<HttpRequest<?>> rejected = request -> FetchMetadataRuleResult.REJECTED;

        new FetchMetadataFilter(List.of(rejected)).filterRequest(HttpRequest.GET("/account"));

        ILoggingEvent event = singleEvent();
        assertEquals(Level.DEBUG, event.getLevel());
        String message = event.getFormattedMessage();
        assertTrue(message.contains("GET /account rejected by rule"), message);
        assertTrue(message.contains("site=<absent>, mode=<absent>, dest=<absent>, origin=<absent>, cookie=<absent>"), message);
    }

    @Test
    void logsParsedFetchMetadataAndSanitizesTheOrigin() {
        FetchMetadataRule<HttpRequest<?>> unknown = request -> FetchMetadataRuleResult.UNKNOWN;
        HttpRequest<?> request = HttpRequest.GET("/account")
            .header(HttpHeaders.SEC_FETCH_SITE, "forged\tvalue")
            .header(HttpHeaders.SEC_FETCH_DEST, "image")
            .header(HttpHeaders.ORIGIN, "https://evil.example/\tx" + "a".repeat(300));

        new FetchMetadataFilter(List.of(unknown)).filterRequest(request);

        String message = singleEvent().getFormattedMessage();
        assertTrue(message.contains("site=<unrecognized>, mode=<absent>, dest=image, origin=https://evil.example/?x"), message);
        assertTrue(message.contains("a".repeat(200 - "https://evil.example/?x".length()) + "..., cookie=<absent>"), message);
        assertFalse(message.contains("forged"), message);
        assertFalse(message.contains("\t"), message);
    }

    @Test
    void doesNotDescribeTheRequestWhenDebugIsDisabled() {
        Level level = logger.getLevel();
        logger.setLevel(Level.INFO);
        try {
            FetchMetadataRule<HttpRequest<?>> unknown = request -> FetchMetadataRuleResult.UNKNOWN;
            FetchMetadataRule<HttpRequest<?>> rejected = request -> FetchMetadataRuleResult.REJECTED;
            FetchMetadataRule<HttpRequest<?>> allowed = request -> FetchMetadataRuleResult.ALLOWED;

            new FetchMetadataFilter(List.of(unknown)).filterRequest(crossSiteRequestWithCookie());
            new FetchMetadataFilter(List.of(rejected)).filterRequest(crossSiteRequestWithCookie());
            new FetchMetadataFilter(List.of(allowed)).filterRequest(crossSiteRequestWithCookie());

            assertTrue(appender.list.isEmpty());
        } finally {
            logger.setLevel(level);
        }
    }

    private ILoggingEvent singleEvent() {
        assertEquals(1, appender.list.size(), appender.list::toString);
        return appender.list.getFirst();
    }

    private static HttpRequest<?> crossSiteRequestWithCookie() {
        return HttpRequest.POST("/account", "")
            .header(HttpHeaders.SEC_FETCH_SITE, "cross-site")
            .header(HttpHeaders.SEC_FETCH_MODE, "navigate")
            .header(HttpHeaders.SEC_FETCH_DEST, "document")
            .header(HttpHeaders.ORIGIN, "https://evil.example")
            .header(HttpHeaders.COOKIE, "SESSION=secret-session-id");
    }
}

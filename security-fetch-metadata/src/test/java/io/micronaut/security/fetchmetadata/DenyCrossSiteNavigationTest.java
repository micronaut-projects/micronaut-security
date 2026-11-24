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
import io.micronaut.context.ApplicationContext;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.Destination;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.Mode;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.Site;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DenyCrossSiteNavigationTest {

    private static final String ANNOTATED = "/fetch-metadata/start";
    private static final String ANNOTATED_CORS = "/fetch-metadata/start-cors";
    private static final String NOT_ANNOTATED = "/fetch-metadata";
    private static final String RULE_LOGGER =
        "io.micronaut.security.fetchmetadata.rules.SimpleTopLevelNavigationAndIframingFetchMetadataRule";

    private static EmbeddedServer defaults;
    private static EmbeddedServer sameSiteAllowed;
    private static EmbeddedServer protectionDisabled;

    @BeforeAll
    static void startServers() {
        defaults = ApplicationContext.run(EmbeddedServer.class);
        sameSiteAllowed = ApplicationContext.run(EmbeddedServer.class,
            Map.of(FetchMetadataRulesConfiguration.PROPERTY_ALLOW_SAME_SITE, StringUtils.TRUE));
        protectionDisabled = ApplicationContext.run(EmbeddedServer.class,
            Map.of(FetchMetadataRulesConfiguration.PROPERTY_DENY_ANNOTATED_CROSS_SITE_NAVIGATION, StringUtils.FALSE));
    }

    @AfterAll
    static void stopServers() {
        for (EmbeddedServer server : new EmbeddedServer[] {defaults, sameSiteAllowed, protectionDisabled}) {
            if (server != null) {
                server.close();
            }
        }
    }

    @ParameterizedTest
    @EnumSource(value = Destination.class, names = {"DOCUMENT", "IFRAME", "FRAME"})
    void rejectsCrossSiteNavigationsToAnAnnotatedRoute(Destination destination) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> status(defaults, navigation(ANNOTATED, Site.CROSS_SITE, destination)));

        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
        assertEquals("no-store", exception.getResponse().getHeaders().get(HttpHeaders.CACHE_CONTROL));
    }

    @Test
    void logsWhyANavigationToAnAnnotatedRouteIsNotAllowed() {
        Logger logger = (Logger) LoggerFactory.getLogger(RULE_LOGGER);
        Level level = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        // set explicitly, so that the test does not depend on logback.xml
        logger.setLevel(Level.DEBUG);
        try {
            assertForbidden(defaults, navigation(ANNOTATED, Site.CROSS_SITE, Destination.DOCUMENT));
        } finally {
            logger.setLevel(level);
            logger.detachAppender(appender);
        }

        assertEquals(1, appender.list.size(), appender.list::toString);
        ILoggingEvent event = appender.list.getFirst();
        assertEquals(Level.DEBUG, event.getLevel());
        String message = event.getFormattedMessage();
        assertTrue(message.contains("Sec-Fetch-Site [cross-site] targets a route annotated with @DenyCrossSiteNavigation"), message);
        assertTrue(message.contains("micronaut.security.fetch-metadata.rules.deny-annotated-cross-site-navigation=false"), message);
        assertTrue(message.contains("#fetchMetadataSensitiveNavigationRoutes"), message);
    }

    // covers the isDebugEnabled guard; the message itself is asserted by the test above
    @Test
    void stillRejectsWithoutLoggingWhenDebugIsDisabled() {
        Logger logger = (Logger) LoggerFactory.getLogger(RULE_LOGGER);
        Level level = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.INFO);
        try {
            assertForbidden(defaults, navigation(ANNOTATED, Site.CROSS_SITE, Destination.DOCUMENT));
        } finally {
            logger.setLevel(level);
            logger.detachAppender(appender);
        }

        assertTrue(appender.list.isEmpty(), appender.list::toString);
    }

    @Test
    void rejectsSameSiteNavigationsToAnAnnotatedRouteByDefault() {
        assertForbidden(defaults, navigation(ANNOTATED, Site.SAME_SITE, Destination.DOCUMENT));
    }

    @Test
    void allowsSameSiteNavigationsToAnAnnotatedRouteWhenSameSiteRequestsAreAllowed() {
        assertEquals(HttpStatus.OK, status(sameSiteAllowed, navigation(ANNOTATED, Site.SAME_SITE, Destination.DOCUMENT)));
        assertForbidden(sameSiteAllowed, navigation(ANNOTATED, Site.CROSS_SITE, Destination.DOCUMENT));
    }

    @Test
    void allowsSameOriginNavigationsToAnAnnotatedRoute() {
        assertEquals(HttpStatus.OK, status(defaults, navigation(ANNOTATED, Site.SAME_ORIGIN, Destination.DOCUMENT)));
    }

    @Test
    void allowsNavigationsStartedFromTheBrowserUiToAnAnnotatedRoute() {
        assertEquals(HttpStatus.OK, status(defaults, navigation(ANNOTATED, Site.NONE, Destination.DOCUMENT)));
    }

    @Test
    void allowsRequestsWithoutFetchMetadataToAnAnnotatedRoute() {
        assertEquals(HttpStatus.OK, status(defaults, HttpRequest.GET(ANNOTATED)));
    }

    @Test
    void stillAllowsCrossSiteNavigationsToRoutesWithoutTheAnnotation() {
        assertEquals(HttpStatus.OK, status(defaults, navigation(NOT_ANNOTATED, Site.CROSS_SITE, Destination.DOCUMENT)));
    }

    @Test
    void allowsCrossSiteNavigationsToAnAnnotatedRouteWhenTheProtectionIsDisabled() {
        assertEquals(HttpStatus.OK, status(protectionDisabled, navigation(ANNOTATED, Site.CROSS_SITE, Destination.DOCUMENT)));
    }

    @Test
    void crossOriginAnnotationDoesNotAllowACrossSiteNavigationWithoutAnOrigin() {
        // browsers do not send an Origin header with GET navigations
        assertForbidden(defaults, navigation(ANNOTATED_CORS, Site.CROSS_SITE, Destination.DOCUMENT));
    }

    @Test
    void crossOriginAnnotationStillAllowsCorsRequestsFromAnAllowedOrigin() {
        MutableHttpRequest<?> request = request(ANNOTATED_CORS, Site.CROSS_SITE, Mode.CORS, Destination.EMPTY)
            .header(HttpHeaders.ORIGIN, "https://allowed.example");

        assertEquals(HttpStatus.OK, status(defaults, request));
    }

    private static void assertForbidden(EmbeddedServer server, HttpRequest<?> request) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> status(server, request));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
    }

    private static HttpStatus status(EmbeddedServer server, HttpRequest<?> request) {
        try (HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            return client.toBlocking().exchange(request, String.class).getStatus();
        }
    }

    private static MutableHttpRequest<?> navigation(String path, Site site, Destination destination) {
        return request(path, site, Mode.NAVIGATE, destination);
    }

    private static MutableHttpRequest<?> request(String path, Site site, Mode mode, Destination destination) {
        return HttpRequest.GET(path)
            .header(HttpHeaders.SEC_FETCH_SITE, site.toString())
            .header(HttpHeaders.SEC_FETCH_MODE, mode.toString())
            .header(HttpHeaders.SEC_FETCH_DEST, destination.toString());
    }
}

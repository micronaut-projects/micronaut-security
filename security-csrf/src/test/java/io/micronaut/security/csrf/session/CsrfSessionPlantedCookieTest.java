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
package io.micronaut.security.csrf.session;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.repository.CsrfTokenRepository;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.session.Session;
import jakarta.inject.Singleton;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With session based authentication, the CSRF token stored in the HTTP session is the only token accepted for a request
 * carrying that session. A CSRF cookie planted in the victim's browser (for example from a sibling subdomain) must not
 * turn the synchronizer token into a double submit cookie.
 */
class CsrfSessionPlantedCookieTest {
    private static final String SPEC_NAME = "CsrfSessionPlantedCookieTest";
    private static final String SESSION_COOKIE = "SESSION";
    private static final String SIGNATURE_KEY = "test-fixture-not-a-secret-csrf-signature-key";

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {SIGNATURE_KEY})
    void plantedCsrfCookieDoesNotBypassTheSessionCsrfToken(String signatureKey) {
        try (EmbeddedServer server = startServer(signatureKey);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            CsrfConfiguration csrfConfiguration = server.getApplicationContext().getBean(CsrfConfiguration.class);

            String victimSessionId = login(client);
            String victimCsrfToken = csrfTokenInSession(client, victimSessionId);
            assertFalse(victimCsrfToken.isBlank());

            // the token stored in the victim's session is accepted
            assertAccepted(client, formPost(victimSessionId, victimCsrfToken));
            assertAccepted(client, headerPost(victimSessionId, victimCsrfToken, csrfConfiguration));

            // an attacker-chosen value planted both as CSRF cookie and as field/header is rejected
            String plantedToken = ".attacker-chosen-value";
            assertRejected(client, formPost(victimSessionId, plantedToken).cookie(csrfCookie(csrfConfiguration, plantedToken)));
            assertRejected(client, headerPost(victimSessionId, plantedToken, csrfConfiguration).cookie(csrfCookie(csrfConfiguration, plantedToken)));

            // a valid token issued for the attacker's own session, planted in the victim's browser, is rejected
            String attackerSessionId = login(client);
            String attackerCsrfToken = csrfTokenInSession(client, attackerSessionId);
            assertNotEquals(victimCsrfToken, attackerCsrfToken);
            assertRejected(client, formPost(victimSessionId, attackerCsrfToken).cookie(csrfCookie(csrfConfiguration, attackerCsrfToken)));
            assertRejected(client, headerPost(victimSessionId, attackerCsrfToken, csrfConfiguration).cookie(csrfCookie(csrfConfiguration, attackerCsrfToken)));

            // the planted cookie alone, without the token in the request, is rejected
            assertRejected(client, formPost(victimSessionId, null).cookie(csrfCookie(csrfConfiguration, plantedToken)));

            // the session token keeps being accepted when a stray CSRF cookie is present: the session is authoritative
            assertAccepted(client, formPost(victimSessionId, victimCsrfToken).cookie(csrfCookie(csrfConfiguration, plantedToken)));
        }
    }

    /**
     * The session is authoritative only while it holds a CSRF token. A session without the {@code csrfToken} attribute
     * (created before CSRF was enabled, or by a login path which does not run {@link CsrfSessionPopulator}) does not
     * neutralize a planted CSRF cookie: the next repository, the cookie repository, is consulted. With a signature key the
     * HMAC binds the token to the session ID, so a token issued for the attacker's session is still rejected.
     */
    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {SIGNATURE_KEY})
    void sessionWithoutCsrfTokenFallsThroughToTheCookieRepository(String signatureKey) {
        try (EmbeddedServer server = startServer(signatureKey);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            CsrfConfiguration csrfConfiguration = server.getApplicationContext().getBean(CsrfConfiguration.class);

            String attackerSessionId = login(client);
            String attackerCsrfToken = csrfTokenInSession(client, attackerSessionId);
            assertFalse(attackerCsrfToken.isBlank());

            String victimSessionId = login(client);
            clearCsrfTokenInSession(client, victimSessionId);
            assertTrue(csrfTokenInSession(client, victimSessionId).isBlank());

            // without a token in the session nor a CSRF cookie, no repository holds a token: rejected
            assertRejected(client, formPost(victimSessionId, attackerCsrfToken));
            assertRejected(client, headerPost(victimSessionId, attackerCsrfToken, csrfConfiguration));

            // the session holds no token, so the planted cookie is consulted
            MutableHttpRequest<?> plantedForm = formPost(victimSessionId, attackerCsrfToken).cookie(csrfCookie(csrfConfiguration, attackerCsrfToken));
            MutableHttpRequest<?> plantedHeader = headerPost(victimSessionId, attackerCsrfToken, csrfConfiguration).cookie(csrfCookie(csrfConfiguration, attackerCsrfToken));
            if (signatureKey == null) {
                // documented limitation: every session-creating login path must run CsrfSessionPopulator
                assertAccepted(client, plantedForm);
                assertAccepted(client, plantedHeader);
            } else {
                // the HMAC is bound to the session ID: a token issued for another session is rejected
                assertRejected(client, plantedForm);
                assertRejected(client, plantedHeader);
            }
        }
    }

    private static EmbeddedServer startServer(String signatureKey) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", SPEC_NAME);
        properties.put("micronaut.security.authentication", "session");
        properties.put("micronaut.security.redirect.enabled", StringUtils.FALSE);
        properties.put("micronaut.security.csrf.filter.regex-pattern", "^(?!\\/login).*$");
        if (signatureKey != null) {
            properties.put("micronaut.security.csrf.signature-key", signatureKey);
        }
        return ApplicationContext.run(EmbeddedServer.class, properties);
    }

    private static String login(BlockingHttpClient client) {
        HttpRequest<?> loginRequest = HttpRequest.POST("/login", Map.of("username", "sherlock", "password", "password"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        HttpResponse<?> loginRsp = assertDoesNotThrow(() -> client.exchange(loginRequest));
        assertEquals(HttpStatus.OK, loginRsp.getStatus());
        Optional<Cookie> sessionCookie = loginRsp.getCookie(SESSION_COOKIE);
        assertTrue(sessionCookie.isPresent());
        return sessionCookie.get().getValue();
    }

    private static String csrfTokenInSession(BlockingHttpClient client, String sessionId) {
        HttpRequest<?> request = HttpRequest.GET("/csrf/echo").cookie(Cookie.of(SESSION_COOKIE, sessionId));
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(request, String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        return response.getBody().orElse("");
    }

    private static void clearCsrfTokenInSession(BlockingHttpClient client, String sessionId) {
        HttpRequest<?> request = HttpRequest.GET("/csrf/clear").cookie(Cookie.of(SESSION_COOKIE, sessionId));
        HttpResponse<?> response = assertDoesNotThrow(() -> client.exchange(request));
        assertEquals(HttpStatus.OK, response.getStatus());
    }

    private static Cookie csrfCookie(CsrfConfiguration csrfConfiguration, String value) {
        return Cookie.of(csrfConfiguration.getCookieName(), value);
    }

    private static MutableHttpRequest<?> formPost(String sessionId, String csrfToken) {
        Map<String, String> form = new HashMap<>(Map.of("username", "sherlock", "password", "evil"));
        if (csrfToken != null) {
            form.put("csrfToken", csrfToken);
        }
        return HttpRequest.POST("/password/change", form)
            .cookie(Cookie.of(SESSION_COOKIE, sessionId))
            .accept(MediaType.TEXT_HTML)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    private static MutableHttpRequest<?> headerPost(String sessionId, String csrfToken, CsrfConfiguration csrfConfiguration) {
        return HttpRequest.POST("/password/change", Map.of("username", "sherlock", "password", "evil"))
            .header(csrfConfiguration.getHeaderName(), csrfToken)
            .cookie(Cookie.of(SESSION_COOKIE, sessionId))
            .accept(MediaType.TEXT_HTML)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    private static void assertAccepted(BlockingHttpClient client, HttpRequest<?> request) {
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(request, String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(Optional.of("sherlock"), response.getBody());
    }

    private static void assertRejected(BlockingHttpClient client, HttpRequest<?> request) {
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(request));
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(List.of(new SuccessAuthenticationScenario("sherlock")));
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class PasswordChangeController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_HTML)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/password/change")
        String changePassword(@Body Map<String, String> form) {
            return form.get("username");
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/csrf")
    static class CsrfTokenEchoController {
        private final CsrfTokenRepository<HttpRequest<?>> csrfTokenRepository;
        private final CsrfConfiguration csrfConfiguration;

        CsrfTokenEchoController(CsrfTokenRepository<HttpRequest<?>> csrfTokenRepository, CsrfConfiguration csrfConfiguration) {
            this.csrfTokenRepository = csrfTokenRepository;
            this.csrfConfiguration = csrfConfiguration;
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/echo")
        String echo(HttpRequest<?> request) {
            return csrfTokenRepository.findCsrfToken(request).orElse("");
        }

        /**
         * Simulates a session created before CSRF was enabled, or by a login path which does not run {@link CsrfSessionPopulator}.
         */
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/clear")
        String clear(Session session) {
            session.remove(csrfConfiguration.getHttpSessionName());
            return "cleared";
        }
    }
}

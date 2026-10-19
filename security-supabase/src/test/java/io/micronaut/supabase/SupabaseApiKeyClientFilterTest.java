package io.micronaut.supabase;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.runtime.server.EmbeddedServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies which API key {@link SupabaseApiKeyClientFilter} attaches to requests of the {@code supabase} client.
 * A recording server stands in for Supabase; each scenario runs a client context with its own keys.
 */
class SupabaseApiKeyClientFilterTest {
    private static final String SPEC_NAME = "SupabaseApiKeyClientFilterTest";
    private static final String PUBLISHABLE_KEY = "sb_publishable_fixture";
    private static final String SECRET_KEY = "sb_secret_fixture";
    private static final String LEGACY_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.fixture-signature";
    private static final String USER_TOKEN = "Bearer user-access-token";

    private static EmbeddedServer server;

    @BeforeAll
    static void startServer() {
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.enabled", false));
    }

    @AfterAll
    static void stopServer() {
        server.close();
    }

    @Test
    void userRouteSendsPublishableKeyAndUserToken() {
        try (ApplicationContext context = clientContext(PUBLISHABLE_KEY, SECRET_KEY)) {
            Map<String, String> headers = context.getBean(RecordingClient.class).user(USER_TOKEN);

            assertEquals(PUBLISHABLE_KEY, headers.get(SupabaseApiKeyClientFilter.APIKEY_HEADER));
            assertEquals(USER_TOKEN, headers.get(HttpHeaders.AUTHORIZATION));
        }
    }

    @Test
    void publicRouteSendsPublishableKeyWithoutAuthorization() {
        try (ApplicationContext context = clientContext(PUBLISHABLE_KEY, SECRET_KEY)) {
            Map<String, String> headers = context.getBean(RecordingClient.class).health();

            assertEquals(PUBLISHABLE_KEY, headers.get(SupabaseApiKeyClientFilter.APIKEY_HEADER));
            assertFalse(headers.containsKey(HttpHeaders.AUTHORIZATION));
        }
    }

    @Test
    void adminRouteSendsSecretKeyOnlyInApikeyHeader() {
        try (ApplicationContext context = clientContext(PUBLISHABLE_KEY, SECRET_KEY)) {
            Map<String, String> headers = context.getBean(RecordingClient.class).adminUsers();

            assertEquals(SECRET_KEY, headers.get(SupabaseApiKeyClientFilter.APIKEY_HEADER));
            assertFalse(headers.containsKey(HttpHeaders.AUTHORIZATION), "opaque secret keys must not be sent as bearer tokens");
        }
    }

    @Test
    void inviteRouteSendsSecretKey() {
        try (ApplicationContext context = clientContext(PUBLISHABLE_KEY, SECRET_KEY)) {
            Map<String, String> headers = context.getBean(RecordingClient.class).invite();

            assertEquals(SECRET_KEY, headers.get(SupabaseApiKeyClientFilter.APIKEY_HEADER));
        }
    }

    @Test
    void legacyServiceRoleKeyIsAlsoSentAsBearerOnAdminRoutes() {
        try (ApplicationContext context = clientContext(PUBLISHABLE_KEY, LEGACY_SERVICE_ROLE_KEY)) {
            Map<String, String> headers = context.getBean(RecordingClient.class).adminUsers();

            assertEquals(LEGACY_SERVICE_ROLE_KEY, headers.get(SupabaseApiKeyClientFilter.APIKEY_HEADER));
            assertEquals("Bearer " + LEGACY_SERVICE_ROLE_KEY, headers.get(HttpHeaders.AUTHORIZATION));
        }
    }

    @Test
    void legacyServiceRoleKeyIsNotSentAsBearerOnUserRoutes() {
        try (ApplicationContext context = clientContext(PUBLISHABLE_KEY, LEGACY_SERVICE_ROLE_KEY)) {
            Map<String, String> headers = context.getBean(RecordingClient.class).health();

            assertEquals(PUBLISHABLE_KEY, headers.get(SupabaseApiKeyClientFilter.APIKEY_HEADER));
            assertFalse(headers.containsKey(HttpHeaders.AUTHORIZATION));
        }
    }

    @Test
    void nothingIsAddedWhenNoKeysAreConfigured() {
        try (ApplicationContext context = clientContext(null, null)) {
            RecordingClient client = context.getBean(RecordingClient.class);

            assertFalse(client.health().containsKey(SupabaseApiKeyClientFilter.APIKEY_HEADER));
            assertFalse(client.adminUsers().containsKey(SupabaseApiKeyClientFilter.APIKEY_HEADER));
            assertFalse(client.adminUsers().containsKey(HttpHeaders.AUTHORIZATION));
        }
    }

    @Test
    void secretKeyIsNotSentOnUserRoutesWhenNoPublishableKeyIsConfigured() {
        try (ApplicationContext context = clientContext(null, SECRET_KEY)) {
            RecordingClient client = context.getBean(RecordingClient.class);

            assertFalse(client.health().containsKey(SupabaseApiKeyClientFilter.APIKEY_HEADER));
            assertEquals(SECRET_KEY, client.adminUsers().get(SupabaseApiKeyClientFilter.APIKEY_HEADER));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin/users", "/admin/users/{userId}", "/auth/v1/admin/sso/providers", "/invite", "/auth/v1/invite", "/admin/audit?page=1"})
    void adminRoutesAreRecognised(String path) {
        assertTrue(SupabaseApiKeyClientFilter.isAdminRoute(path));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/user", "/token", "/health", "/auth/v1/user", "/factors/{factorId}/verify", "/invitee", "/oauth/clients/register"})
    void userRoutesAreNotAdminRoutes(String path) {
        assertFalse(SupabaseApiKeyClientFilter.isAdminRoute(path));
    }

    private static ApplicationContext clientContext(String publishableKey, String secretKey) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", SPEC_NAME);
        properties.put("micronaut.http.services." + SupabaseApiKeyClientFilter.SERVICE_ID + ".url", server.getURL().toString());
        if (publishableKey != null) {
            properties.put("supabase.publishable-key", publishableKey);
        }
        if (secretKey != null) {
            properties.put("supabase.secret-key", secretKey);
        }
        return ApplicationContext.run(properties);
    }

    /**
     * Declarative client with the same service id as {@code SupabaseAuthClient}, so the filter applies to it.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Client(id = SupabaseApiKeyClientFilter.SERVICE_ID)
    interface RecordingClient {
        @Get("/user")
        Map<String, String> user(@Header(HttpHeaders.AUTHORIZATION) String authorization);

        @Get("/health")
        Map<String, String> health();

        @Get("/admin/users")
        Map<String, String> adminUsers();

        @Post("/invite")
        Map<String, String> invite();
    }

    /**
     * Echoes the credential headers it received.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class RecordingController {
        @Get("/user")
        Map<String, String> user(HttpHeaders headers) {
            return credentials(headers);
        }

        @Get("/health")
        Map<String, String> health(HttpHeaders headers) {
            return credentials(headers);
        }

        @Get("/admin/users")
        Map<String, String> adminUsers(HttpHeaders headers) {
            return credentials(headers);
        }

        @Post("/invite")
        Map<String, String> invite(HttpHeaders headers) {
            return credentials(headers);
        }

        private static Map<String, String> credentials(HttpHeaders headers) {
            Map<String, String> credentials = new HashMap<>();
            headers.findFirst(SupabaseApiKeyClientFilter.APIKEY_HEADER).ifPresent(v -> credentials.put(SupabaseApiKeyClientFilter.APIKEY_HEADER, v));
            headers.findFirst(HttpHeaders.AUTHORIZATION).ifPresent(v -> credentials.put(HttpHeaders.AUTHORIZATION, v));
            return credentials;
        }
    }
}

package io.micronaut.supabase.management;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.runtime.server.EmbeddedServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@link SupabaseManagementAccessTokenClientFilter} sends the configured access token as the
 * bearer token of the {@code supabase-management} client, and only of that client.
 */
class SupabaseManagementAccessTokenClientFilterTest {
    private static final String SPEC_NAME = "SupabaseManagementAccessTokenClientFilterTest";
    private static final String ACCESS_TOKEN = "sbp_fixture_personal_access_token";

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
    void configuredTokenIsSentAsBearer() {
        try (ApplicationContext context = clientContext(ACCESS_TOKEN)) {
            assertEquals(Optional.of("Bearer " + ACCESS_TOKEN), context.getBean(ManagementClient.class).authorization());
        }
    }

    @Test
    void explicitAuthorizationHeaderIsKept() {
        try (ApplicationContext context = clientContext(ACCESS_TOKEN)) {
            assertEquals(Optional.of("Bearer sbp_fixture_other_token"),
                context.getBean(ManagementClient.class).authorization("Bearer sbp_fixture_other_token"));
        }
    }

    @Test
    void nothingIsAddedWithoutAConfiguredToken() {
        try (ApplicationContext context = clientContext(null)) {
            assertTrue(context.getBean(ManagementClient.class).authorization().isEmpty());
        }
    }

    @Test
    void blankTokenIsNotSent() {
        try (ApplicationContext context = clientContext("")) {
            assertTrue(context.getBean(ManagementClient.class).authorization().isEmpty());
        }
    }

    @Test
    void otherClientsAreNotFiltered() {
        try (ApplicationContext context = clientContext(ACCESS_TOKEN)) {
            assertTrue(context.getBean(OtherClient.class).authorization().isEmpty());
        }
    }

    private static ApplicationContext clientContext(String accessToken) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", SPEC_NAME);
        properties.put("micronaut.http.services." + SupabaseManagementConfiguration.SERVICE_ID + ".url", server.getURL().toString());
        properties.put("micronaut.http.services.other.url", server.getURL().toString());
        if (accessToken != null) {
            properties.put("supabase.management.access-token", accessToken);
        }
        return ApplicationContext.run(properties);
    }

    /**
     * Declarative client with the same service id as the Management API clients, so the filter applies to it.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Client(id = SupabaseManagementConfiguration.SERVICE_ID)
    interface ManagementClient {
        @Get("/v1/profile")
        Optional<String> authorization();

        @Get("/v1/profile")
        Optional<String> authorization(@Header(HttpHeaders.AUTHORIZATION) String authorization);
    }

    /**
     * Declarative client with another service id, which the filter must leave alone.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Client(id = "other")
    interface OtherClient {
        @Get("/v1/profile")
        Optional<String> authorization();
    }

    /**
     * Echoes the {@code Authorization} header it received, or an empty body.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/v1/profile")
    static class ProfileController {
        @Get
        Optional<String> profile(@Header(HttpHeaders.AUTHORIZATION) Optional<String> authorization) {
            return authorization;
        }
    }
}

package io.micronaut.supabase.secrets;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.supabase.management.SupabaseManagementConfiguration;
import jakarta.inject.Singleton;
import jakarta.validation.ConstraintViolationException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link SupabaseSecretsClient} against an in-memory stand-in for the Secrets resource of the
 * Management API that enforces the bearer token and follows the OpenAPI document: {@code 201} without a body on
 * creation, {@code 200} without a body on deletion, replacement of existing names, and {@code 401} without a
 * body for a missing or wrong token.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SupabaseSecretsClientTest {
    private static final String SPEC_NAME = "SupabaseSecretsClientTest";
    private static final String ACCESS_TOKEN = "sbp_fixture_personal_access_token";
    private static final String REF = "abcdefghijklmnopqrst";
    private static final String OTHER_REF = "tsrqponmlkjihgfedcba";

    private EmbeddedServer server;
    private ApplicationContext clientContext;
    private SupabaseSecretsClient client;
    private SecretsStore store;

    @BeforeAll
    void start() {
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.enabled", false));
        store = server.getApplicationContext().getBean(SecretsStore.class);
        clientContext = ApplicationContext.run(Map.of(
            "spec.name", SPEC_NAME,
            "supabase.management.url", server.getURL().toString(),
            "supabase.management.access-token", ACCESS_TOKEN));
        client = clientContext.getBean(SupabaseSecretsClient.class);
    }

    @AfterEach
    void clearSecrets() {
        store.clear();
    }

    @AfterAll
    void stop() {
        clientContext.close();
        server.close();
    }

    @Test
    void listOfAProjectWithoutSecretsIsEmpty() {
        HttpResponse<List<SecretResponse>> response = client.list(REF);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals(List.of(), response.body());
    }

    @Test
    void createdSecretsAreListedWithTheirValues() {
        HttpResponse<?> created = client.create(REF, List.of(
            new CreateSecretRequest("OPENAI_API_KEY", "sk-example-secret"),
            new CreateSecretRequest("STRIPE_WEBHOOK_SECRET", "whsec_example")));

        assertEquals(HttpStatus.CREATED, created.getStatus());
        assertEquals(Optional.empty(), created.getBody());
        assertEquals(List.of("Bearer " + ACCESS_TOKEN), store.authorizations());

        List<SecretResponse> secrets = client.list(REF).body();
        assertNotNull(secrets);
        assertEquals(2, secrets.size());
        assertEquals(new SecretResponse("OPENAI_API_KEY", "sk-example-secret", SecretsStore.UPDATED_AT), secrets.get(0));
        assertEquals(new SecretResponse("STRIPE_WEBHOOK_SECRET", "whsec_example", SecretsStore.UPDATED_AT), secrets.get(1));
    }

    @Test
    void creatingAnExistingNameReplacesItsValue() {
        client.create(REF, List.of(new CreateSecretRequest("OPENAI_API_KEY", "sk-first")));
        client.create(REF, List.of(new CreateSecretRequest("OPENAI_API_KEY", "sk-second")));

        List<SecretResponse> secrets = client.list(REF).body();
        assertNotNull(secrets);
        assertEquals(1, secrets.size());
        assertEquals("sk-second", secrets.getFirst().value());
    }

    @Test
    void secretsBelongToTheProjectTheyWereCreatedIn() {
        client.create(REF, List.of(new CreateSecretRequest("OPENAI_API_KEY", "sk-example-secret")));

        assertEquals(List.of(), client.list(OTHER_REF).body());
    }

    @Test
    void deletedSecretsAreNoLongerListed() {
        client.create(REF, List.of(
            new CreateSecretRequest("OPENAI_API_KEY", "sk-example-secret"),
            new CreateSecretRequest("STRIPE_WEBHOOK_SECRET", "whsec_example")));

        HttpResponse<?> deleted = client.delete(REF, List.of("OPENAI_API_KEY", "UNKNOWN"));

        assertEquals(HttpStatus.OK, deleted.getStatus());
        assertEquals(Optional.empty(), deleted.getBody());
        List<SecretResponse> secrets = client.list(REF).body();
        assertNotNull(secrets);
        assertEquals(1, secrets.size());
        assertEquals("STRIPE_WEBHOOK_SECRET", secrets.getFirst().name());
    }

    @Test
    void requestsWithoutAnAccessTokenAreUnauthorized() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            "spec.name", SPEC_NAME,
            "supabase.management.url", server.getURL().toString()))) {
            SupabaseSecretsClient anonymous = context.getBean(SupabaseSecretsClient.class);

            HttpClientResponseException listing = assertThrows(HttpClientResponseException.class, () -> anonymous.list(REF));
            assertEquals(HttpStatus.UNAUTHORIZED, listing.getStatus());
            HttpClientResponseException creation = assertThrows(HttpClientResponseException.class,
                () -> anonymous.create(REF, List.of(new CreateSecretRequest("OPENAI_API_KEY", "sk-example-secret"))));
            assertEquals(HttpStatus.UNAUTHORIZED, creation.getStatus());
            HttpClientResponseException deletion = assertThrows(HttpClientResponseException.class,
                () -> anonymous.delete(REF, List.of("OPENAI_API_KEY")));
            assertEquals(HttpStatus.UNAUTHORIZED, deletion.getStatus());
            assertEquals(List.of(), client.list(REF).body(), "the rejected creation must not have stored anything");
        }
    }

    @Test
    void requestsWithAWrongAccessTokenAreUnauthorized() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            "spec.name", SPEC_NAME,
            "supabase.management.url", server.getURL().toString(),
            "supabase.management.access-token", "sbp_fixture_revoked_token"))) {
            SupabaseSecretsClient revoked = context.getBean(SupabaseSecretsClient.class);

            HttpClientResponseException e = assertThrows(HttpClientResponseException.class, () -> revoked.list(REF));
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
            assertEquals(Optional.empty(), e.getResponse().getBody());
        }
    }

    @Test
    void reservedNamesAreRejectedBeforeTheRequestIsSent() {
        assertThrows(ConstraintViolationException.class,
            () -> client.create(REF, List.of(new CreateSecretRequest("SUPABASE_URL", "https://example.supabase.co"))));

        assertEquals(List.of(), store.authorizations());
    }

    @Test
    void emptyBodiesAreRejectedBeforeTheRequestIsSent() {
        assertThrows(ConstraintViolationException.class, () -> client.create(REF, List.of()));
        assertThrows(ConstraintViolationException.class, () -> client.delete(REF, List.of()));
        assertThrows(ConstraintViolationException.class, () -> client.delete(REF, List.of("")));

        assertEquals(List.of(), store.authorizations());
    }

    @Test
    void moreThanOneHundredSecretsAreRejectedBeforeTheRequestIsSent() {
        List<CreateSecretRequest> secrets = new ArrayList<>();
        for (int i = 0; i <= SupabaseSecretsClient.MAX_SECRETS_PER_REQUEST; i++) {
            secrets.add(new CreateSecretRequest("SECRET_" + i, "value-" + i));
        }

        assertThrows(ConstraintViolationException.class, () -> client.create(REF, secrets));

        assertEquals(List.of(), store.authorizations());
    }

    @Test
    void blankProjectReferencesAreRejectedBeforeTheRequestIsSent() {
        assertThrows(ConstraintViolationException.class, () -> client.list(" "));

        assertEquals(List.of(), store.authorizations());
    }

    /**
     * Secrets of every project, keyed by project reference, plus the {@code Authorization} headers received.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class SecretsStore {
        static final String UPDATED_AT = "2026-10-18T09:15:00Z";

        private final Map<String, Map<String, String>> projects = new ConcurrentHashMap<>();
        private final List<String> authorizations = Collections.synchronizedList(new ArrayList<>());

        Map<String, String> project(String ref) {
            return projects.computeIfAbsent(ref, r -> Collections.synchronizedMap(new LinkedHashMap<>()));
        }

        List<String> authorizations() {
            return List.copyOf(authorizations);
        }

        void record(String authorization) {
            authorizations.add(authorization);
        }

        void clear() {
            projects.clear();
            authorizations.clear();
        }
    }

    /**
     * Stand-in for {@code /v1/projects/{ref}/secrets}.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller(SupabaseSecretsClient.PROJECTS_PATH)
    static class SecretsController {
        private final SecretsStore store;

        SecretsController(SecretsStore store) {
            this.store = store;
        }

        @Get("/{ref}/secrets")
        HttpResponse<List<Map<String, String>>> list(@PathVariable String ref, @Header(HttpHeaders.AUTHORIZATION) Optional<String> authorization) {
            if (!authorized(authorization)) {
                return HttpResponse.unauthorized();
            }
            List<Map<String, String>> secrets = new ArrayList<>();
            store.project(ref).forEach((name, value) -> {
                Map<String, String> secret = new LinkedHashMap<>();
                secret.put("name", name);
                secret.put("value", value);
                secret.put("updated_at", SecretsStore.UPDATED_AT);
                secrets.add(secret);
            });
            return HttpResponse.ok(secrets);
        }

        @Post("/{ref}/secrets")
        HttpResponse<?> create(@PathVariable String ref, @Body List<Map<String, String>> secrets, @Header(HttpHeaders.AUTHORIZATION) Optional<String> authorization) {
            if (!authorized(authorization)) {
                return HttpResponse.unauthorized();
            }
            Map<String, String> project = store.project(ref);
            secrets.forEach(secret -> project.put(secret.get("name"), secret.get("value")));
            return HttpResponse.status(HttpStatus.CREATED);
        }

        @Delete("/{ref}/secrets")
        HttpResponse<?> delete(@PathVariable String ref, @Body List<String> names, @Header(HttpHeaders.AUTHORIZATION) Optional<String> authorization) {
            if (!authorized(authorization)) {
                return HttpResponse.unauthorized();
            }
            Map<String, String> project = store.project(ref);
            names.forEach(project::remove);
            return HttpResponse.ok();
        }

        private boolean authorized(Optional<String> authorization) {
            authorization.ifPresent(store::record);
            return authorization.filter(("Bearer " + ACCESS_TOKEN)::equals).isPresent();
        }
    }
}

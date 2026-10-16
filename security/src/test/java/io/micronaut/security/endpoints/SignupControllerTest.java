package io.micronaut.security.endpoints;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.handlers.SignupHandler;
import jakarta.annotation.PreDestroy;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link SignupController} against a real Supabase Auth (GoTrue) server
 * started with Testcontainers. See <a href="https://github.com/supabase/auth">supabase/auth</a>.
 */
@Testcontainers(disabledWithoutDocker = true)
class SignupControllerTest {

    private static final Logger LOG = LoggerFactory.getLogger(SignupControllerTest.class);

    private static final String SPEC_NAME = "SignupControllerTest";
    private static final String SUPABASE_URL_PROPERTY = "supabase.auth.url";

    private static final String POSTGRES_IMAGE = "postgres:17-alpine";
    private static final String SUPABASE_AUTH_IMAGE = "supabase/auth:v2.197.0";
    private static final int POSTGRES_PORT = 5432;
    private static final int SUPABASE_AUTH_PORT = 9999;
    private static final String POSTGRES_ALIAS = "postgres";
    private static final String DB_NAMESPACE = "auth";

    // Non-secret fixtures: these only exist inside throwaway test containers.
    @SuppressWarnings("java:S2068")
    private static final String POSTGRES_PASSWORD = "postgres";
    @SuppressWarnings("java:S2068")
    private static final String AUTH_ADMIN_PASSWORD = "root";
    @SuppressWarnings("java:S2068")
    private static final String JWT_SECRET = "signup-controller-test-jwt-secret-with-at-least-32-chars";

    /**
     * Mirrors {@code init_postgres.sh} from the supabase/auth repository: the auth server
     * connects as {@code supabase_auth_admin} and runs its migrations in the {@code auth} schema.
     */
    private static final String INIT_SQL = """
        CREATE USER supabase_admin LOGIN CREATEROLE CREATEDB REPLICATION BYPASSRLS;
        CREATE USER supabase_auth_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION PASSWORD '%s';
        CREATE SCHEMA IF NOT EXISTS %s AUTHORIZATION supabase_auth_admin;
        GRANT CREATE ON DATABASE postgres TO supabase_auth_admin;
        ALTER USER supabase_auth_admin SET search_path = '%s';
        """.formatted(AUTH_ADMIN_PASSWORD, DB_NAMESPACE, DB_NAMESPACE);

    private static final Network NETWORK = Network.newNetwork();

    @Container
    private static final GenericContainer<?> POSTGRES = new GenericContainer<>(POSTGRES_IMAGE)
        .withNetwork(NETWORK)
        .withNetworkAliases(POSTGRES_ALIAS)
        .withEnv(Map.of(
            "POSTGRES_USER", "postgres",
            "POSTGRES_PASSWORD", POSTGRES_PASSWORD,
            "POSTGRES_DB", "postgres"
        ))
        .withCopyToContainer(Transferable.of(INIT_SQL), "/docker-entrypoint-initdb.d/init.sql")
        .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*\\n", 2)
            .withStartupTimeout(Duration.ofMinutes(2)));

    @Container
    private static final GenericContainer<?> SUPABASE_AUTH = new GenericContainer<>(SUPABASE_AUTH_IMAGE)
        .dependsOn(POSTGRES)
        .withNetwork(NETWORK)
        .withExposedPorts(SUPABASE_AUTH_PORT)
        .withEnv(Map.ofEntries(
            Map.entry("GOTRUE_API_HOST", "0.0.0.0"),
            Map.entry("GOTRUE_API_PORT", String.valueOf(SUPABASE_AUTH_PORT)),
            Map.entry("API_EXTERNAL_URL", "http://localhost:" + SUPABASE_AUTH_PORT),
            Map.entry("GOTRUE_SITE_URL", "http://localhost:3000"),
            Map.entry("GOTRUE_DB_DRIVER", "postgres"),
            Map.entry("GOTRUE_DB_DATABASE_URL", "postgres://supabase_auth_admin:" + AUTH_ADMIN_PASSWORD
                + "@" + POSTGRES_ALIAS + ":" + POSTGRES_PORT + "/postgres"),
            Map.entry("DB_NAMESPACE", DB_NAMESPACE),
            Map.entry("GOTRUE_JWT_SECRET", JWT_SECRET),
            Map.entry("GOTRUE_JWT_EXP", "3600"),
            Map.entry("GOTRUE_JWT_AUD", "authenticated"),
            Map.entry("GOTRUE_JWT_ADMIN_ROLES", "service_role"),
            Map.entry("GOTRUE_DISABLE_SIGNUP", "false"),
            Map.entry("GOTRUE_EXTERNAL_EMAIL_ENABLED", "true"),
            Map.entry("GOTRUE_MAILER_AUTOCONFIRM", "true"),
            Map.entry("GOTRUE_LOG_LEVEL", "info")
        ))
        .withLogConsumer(new Slf4jLogConsumer(LOG).withPrefix("SUPABASE_AUTH"))
        .waitingFor(Wait.forHttp("/health")
            .forPort(SUPABASE_AUTH_PORT)
            .forStatusCode(200)
            .withStartupTimeout(Duration.ofMinutes(3)));

    private static EmbeddedServer server;
    private static HttpClient httpClient;
    private static BlockingHttpClient client;

    @BeforeAll
    static void startServer() {
        String supabaseUrl = "http://" + SUPABASE_AUTH.getHost() + ":" + SUPABASE_AUTH.getMappedPort(SUPABASE_AUTH_PORT);
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            SUPABASE_URL_PROPERTY, supabaseUrl
        ));
        httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        client = httpClient.toBlocking();
    }

    @AfterAll
    static void stopServer() {
        if (httpClient != null) {
            httpClient.close();
        }
        if (server != null) {
            server.close();
        }
    }

    @Test
    void signupWithEmailAndPasswordReturnsSupabaseSession() {
        Map<String, Object> body = Map.of("email", "alice@example.com", "password", "correct-horse-battery");

        HttpResponse<Map<String, Object>> response = client.exchange(HttpRequest.POST("/signup", body), MAP_ARGUMENT);

        assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Object> session = response.body();
        assertNotNull(session);
        assertEquals("bearer", session.get("token_type"));
        String accessToken = (String) session.get("access_token");
        assertNotNull(accessToken);
        assertTrue(accessToken.split("\\.").length == 3, "access_token should be a JWT");
        String payload = new String(Base64.getUrlDecoder().decode(accessToken.split("\\.")[1]));
        assertTrue(payload.contains("\"aud\":\"authenticated\""), payload);
        assertTrue(payload.contains("\"email\":\"alice@example.com\""), payload);

        @SuppressWarnings("unchecked")
        Map<String, Object> user = (Map<String, Object>) session.get("user");
        assertNotNull(user);
        assertEquals("alice@example.com", user.get("email"));
        assertNotNull(user.get("id"));
    }

    @Test
    void signupWithTooShortPasswordIsRejected() {
        Map<String, Object> body = Map.of("email", "bob@example.com", "password", "123");

        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.POST("/signup", body), MAP_ARGUMENT));

        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, ex.getStatus());
        Map<String, Object> error = ex.getResponse().getBody(MAP_ARGUMENT).orElseThrow();
        assertEquals("weak_password", error.get("error_code"));
    }

    @Test
    void signupWithAlreadyRegisteredEmailIsRejected() {
        Map<String, Object> body = Map.of("email", "carol@example.com", "password", "correct-horse-battery");
        assertEquals(HttpStatus.OK, client.exchange(HttpRequest.POST("/signup", body), MAP_ARGUMENT).getStatus());

        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.POST("/signup", body), MAP_ARGUMENT));

        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, ex.getStatus());
        Map<String, Object> error = ex.getResponse().getBody(MAP_ARGUMENT).orElseThrow();
        assertEquals("user_already_exists", error.get("error_code"));
    }

    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);

    /**
     * A {@link SignupHandler} that forwards the signup body to Supabase Auth's {@code POST /signup}
     * and relays the upstream status and body back to the caller.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class SupabaseSignupHandler implements SignupHandler<HttpRequest<?>, HttpResponse<?>> {

        private final HttpClient supabaseClient;

        SupabaseSignupHandler(@Property(name = SUPABASE_URL_PROPERTY) String supabaseUrl) throws MalformedURLException {
            this.supabaseClient = HttpClient.create(URI.create(supabaseUrl).toURL());
        }

        @Override
        public HttpResponse<?> signup(HttpRequest<?> request, Map<String, Object> body) {
            try {
                HttpResponse<Map<String, Object>> upstream = supabaseClient.toBlocking()
                    .exchange(HttpRequest.POST("/signup", body), MAP_ARGUMENT);
                return HttpResponse.status(upstream.getStatus()).body(upstream.body());
            } catch (HttpClientResponseException e) {
                return HttpResponse.status(e.getStatus()).body(e.getResponse().getBody(MAP_ARGUMENT).orElse(null));
            }
        }

        @PreDestroy
        void close() {
            supabaseClient.close();
        }
    }
}

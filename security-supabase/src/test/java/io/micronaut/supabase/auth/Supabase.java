package io.micronaut.supabase.auth;

import io.micronaut.security.token.ClaimsUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;

import java.time.Duration;
import java.util.Map;

public final class Supabase {
    private static final Logger LOG = LoggerFactory.getLogger(Supabase.class);

    static final String SUPABASE_URL_PROPERTY = "supabase.auth.url";

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
    private static final String HTTP = "http://";

    private Supabase() {
    }

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

    public static Map<String, String> getProperties() {
        String baseUrl = HTTP  + SUPABASE_AUTH.getHost() + ":" + SUPABASE_AUTH.getMappedPort(SUPABASE_AUTH_PORT);
        return Map.of(
            SUPABASE_URL_PROPERTY, baseUrl,
            "micronaut.security.token.jwt.signatures.jwks.supabase.url", baseUrl + "/auth/v1/.well-known/jwks.json",
            "micronaut.http.services.supabase.url", baseUrl);

    }
}

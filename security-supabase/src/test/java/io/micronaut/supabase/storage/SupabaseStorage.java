package io.micronaut.supabase.storage;

import io.micronaut.supabase.SupabaseConfiguration;
import io.micronaut.supabase.auth.Supabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Starts a real Supabase Storage API server with Testcontainers, backed by the PostgreSQL container of
 * {@link Supabase}, and exposes the Micronaut configuration needed to talk to it.
 *
 * <p>The server runs in single-tenant mode with the file backend, signs and verifies tokens with the same
 * HS256 secret as the Auth container, and has versioning and lifecycle rules enabled. Image transformation is
 * disabled because it needs an imgproxy deployment, so the {@code /render/image/**} routes do not exist.</p>
 *
 * @see <a href="https://github.com/supabase/storage">supabase/storage</a>
 */
public final class SupabaseStorage {
    private static final Logger LOG = LoggerFactory.getLogger(SupabaseStorage.class);

    private static final String STORAGE_IMAGE = "supabase/storage-api:v1.83.5";
    private static final int STORAGE_PORT = 5000;
    private static final String HTTP = "http://";

    private static final GenericContainer<?> STORAGE = new GenericContainer<>(STORAGE_IMAGE)
        .withNetwork(Supabase.network())
        .withExposedPorts(STORAGE_PORT)
        .withEnv(storageEnvironment())
        .withLogConsumer(new Slf4jLogConsumer(LOG).withPrefix("SUPABASE_STORAGE"))
        .waitingFor(Wait.forLogMessage(".*Started Successfully.*\\n", 1)
            .withStartupTimeout(Duration.ofMinutes(3)));

    private SupabaseStorage() {
    }

    private static Map<String, String> storageEnvironment() {
        Map<String, String> env = new HashMap<>();
        env.put("SERVER_PORT", String.valueOf(STORAGE_PORT));
        // Same secret as GoTrue, so tokens issued by the Auth container are accepted by Storage.
        env.put("AUTH_JWT_SECRET", Supabase.jwtSecret());
        env.put("AUTH_JWT_ALGORITHM", "HS256");
        // Single tenant mode against the shared database; migrations run as the superuser and create the
        // anon, authenticated and service_role roles when they are missing.
        env.put("DATABASE_URL", Supabase.postgresNetworkUrl());
        env.put("DB_INSTALL_ROLES", "true");
        env.put("TENANT_ID", "storage-single-tenant");
        // Objects are stored on the container's filesystem.
        env.put("STORAGE_BACKEND", "file");
        env.put("STORAGE_FILE_BACKEND_PATH", "/tmp/storage");
        env.put("STORAGE_VERSIONING_ENABLED", "true");
        env.put("STORAGE_LIFECYCLE_ENABLED", "true");
        env.put("IMAGE_TRANSFORMATION_ENABLED", "false");
        env.put("UPLOAD_FILE_SIZE_LIMIT", "52428800");
        env.put("UPLOAD_SIGNED_URL_EXPIRATION_TIME", "120");
        env.put("TUS_URL_PATH", "/upload/resumable");
        env.put("LOG_LEVEL", "info");
        return env;
    }

    private static synchronized void start() {
        if (!STORAGE.isRunning()) {
            Supabase.postgres();
            STORAGE.start();
        }
    }

    public static String baseUrl() {
        start();
        return HTTP + STORAGE.getHost() + ":" + STORAGE.getMappedPort(STORAGE_PORT);
    }

    /**
     * Configuration for the {@code supabase} client to address the Storage container directly.
     */
    public static Map<String, String> getProperties() {
        return Map.of(
            "micronaut.http.services.supabase.url", baseUrl(),
            // The container is a bare Storage API server without the Supabase gateway: the API lives at its root.
            SupabaseConfiguration.STORAGE_PATH_PROPERTY, "",
            "supabase.publishable-key", "sb_publishable_test_fixture");
    }

    /**
     * {@code Authorization} header value of a legacy service-role JWT, which bypasses Row Level Security.
     */
    public static String serviceAuthorization() {
        return "Bearer " + Supabase.serviceRoleJwt();
    }

    /**
     * {@code Authorization} header value of a legacy anon JWT, subject to Row Level Security.
     */
    public static String anonAuthorization() {
        return "Bearer " + Supabase.anonJwt();
    }
}

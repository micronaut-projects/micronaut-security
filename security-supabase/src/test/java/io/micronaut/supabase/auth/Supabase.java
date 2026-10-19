package io.micronaut.supabase.auth;

import io.micronaut.supabase.SupabaseConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Starts a real Supabase Auth (GoTrue) server backed by PostgreSQL with Testcontainers and exposes
 * the Micronaut configuration and test helpers needed to talk to it.
 */
public final class Supabase {
    private static final Logger LOG = LoggerFactory.getLogger(Supabase.class);

    public static final String SUPABASE_URL_PROPERTY = "supabase.auth.url";
    static final String PUBLISHABLE_KEY_PROPERTY = "supabase.publishable-key";
    static final String SECRET_KEY_PROPERTY = "supabase.secret-key";
    /** Publishable key fixture. Direct GoTrue ignores the {@code apikey} header, so any value works. */
    static final String PUBLISHABLE_KEY = "sb_publishable_test_fixture";

    /** {@code GOTRUE_SITE_URL}: GoTrue redirects to this host after email verification and OAuth flows. */
    static final String SITE_URL = "http://localhost:3000";
    /** {@code GOTRUE_OAUTH_SERVER_AUTHORIZATION_PATH}: the consent page GoTrue redirects OAuth clients to. */
    static final String OAUTH_AUTHORIZATION_PATH = "/oauth/consent";
    /** Client id configured for the GitHub external provider. A dummy value, GitHub is never contacted. */
    static final String GITHUB_CLIENT_ID = "github-test-client-id";
    static final String SERVICE_ROLE = "service_role";
    /**
     * Hostname for custom OAuth provider URLs. GoTrue only accepts {@code https} URLs whose host resolves to
     * a public address, so the auth container maps it to a TEST-NET-3 address. It is never connected to.
     */
    static final String CUSTOM_PROVIDER_HOST = "idp.acme.test";
    private static final String CUSTOM_PROVIDER_IP = "203.0.113.10";
    static final String TEST_PASSWORD = "correct-horse-battery";

    private static final String POSTGRES_IMAGE = "postgres:17-alpine";
    private static final String SUPABASE_AUTH_IMAGE = "supabase/auth:v2.197.0";
    private static final int POSTGRES_PORT = 5432;
    private static final int SUPABASE_AUTH_PORT = 9999;
    /**
     * {@code GOTRUE_JWT_ISSUER}: the {@code iss} claim of issued tokens. Hosted projects use
     * {@code https://<project-ref>.supabase.co/auth/v1}; this mirrors that shape for the container.
     */
    public static final String JWT_ISSUER = "http://localhost:" + SUPABASE_AUTH_PORT + "/auth/v1";
    private static final String POSTGRES_ALIAS = "postgres";
    private static final String DB_NAMESPACE = "auth";

    // Non-secret fixtures: these only exist inside throwaway test containers.
    @SuppressWarnings("java:S2068")
    private static final String POSTGRES_PASSWORD = "postgres";
    @SuppressWarnings("java:S2068")
    private static final String AUTH_ADMIN_PASSWORD = "root";
    @SuppressWarnings("java:S2068")
    private static final String JWT_SECRET = "signup-controller-test-jwt-secret-with-at-least-32-chars";
    @SuppressWarnings("java:S2068")
    private static final String GITHUB_CLIENT_SECRET = "github-test-client-secret";
    private static final String HTTP = "http://";

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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
        .withExtraHost(CUSTOM_PROVIDER_HOST, CUSTOM_PROVIDER_IP)
        .withEnv(goTrueEnvironment())
        .withLogConsumer(new Slf4jLogConsumer(LOG).withPrefix("SUPABASE_AUTH"))
        .waitingFor(Wait.forHttp("/health")
            .forPort(SUPABASE_AUTH_PORT)
            .forStatusCode(200)
            .withStartupTimeout(Duration.ofMinutes(3)));

    private static Map<String, String> goTrueEnvironment() {
        Map<String, String> env = new HashMap<>();
        env.put("GOTRUE_API_HOST", "0.0.0.0");
        env.put("GOTRUE_API_PORT", String.valueOf(SUPABASE_AUTH_PORT));
        env.put("API_EXTERNAL_URL", "http://localhost:" + SUPABASE_AUTH_PORT);
        env.put("GOTRUE_SITE_URL", SITE_URL);
        env.put("GOTRUE_URI_ALLOW_LIST", SITE_URL + "/**");
        env.put("GOTRUE_DB_DRIVER", "postgres");
        env.put("GOTRUE_DB_DATABASE_URL", "postgres://supabase_auth_admin:" + AUTH_ADMIN_PASSWORD
            + "@" + POSTGRES_ALIAS + ":" + POSTGRES_PORT + "/postgres");
        env.put("DB_NAMESPACE", DB_NAMESPACE);
        env.put("GOTRUE_JWT_SECRET", JWT_SECRET);
        env.put("GOTRUE_JWT_EXP", "3600");
        env.put("GOTRUE_JWT_AUD", "authenticated");
        env.put("GOTRUE_JWT_ISSUER", JWT_ISSUER);
        env.put("GOTRUE_JWT_DEFAULT_GROUP_NAME", "authenticated");
        env.put("GOTRUE_JWT_ADMIN_ROLES", SERVICE_ROLE);
        env.put("GOTRUE_DISABLE_SIGNUP", "false");
        env.put("GOTRUE_EXTERNAL_EMAIL_ENABLED", "true");
        env.put("GOTRUE_MAILER_AUTOCONFIRM", "true");
        env.put("GOTRUE_LOG_LEVEL", "info");
        // Without GOTRUE_SMTP_HOST GoTrue uses a no-op mailer; raise the per-hour email quota so tests never hit it.
        env.put("GOTRUE_RATE_LIMIT_EMAIL_SENT", "1000");
        // Identity linking: GET /user/identities/authorize and DELETE /user/identities/{id}
        env.put("GOTRUE_SECURITY_MANUAL_LINKING_ENABLED", "true");
        // External OAuth provider so that GET /authorize can redirect. GitHub is never contacted.
        env.put("GOTRUE_EXTERNAL_GITHUB_ENABLED", "true");
        env.put("GOTRUE_EXTERNAL_GITHUB_CLIENT_ID", GITHUB_CLIENT_ID);
        env.put("GOTRUE_EXTERNAL_GITHUB_SECRET", GITHUB_CLIENT_SECRET);
        env.put("GOTRUE_EXTERNAL_GITHUB_REDIRECT_URI", "http://localhost:" + SUPABASE_AUTH_PORT + "/callback");
        // MFA recovery codes: /factors/recovery-codes/**
        env.put("GOTRUE_MFA_RECOVERY_CODES_ENROLL_ENABLED", "true");
        env.put("GOTRUE_MFA_RECOVERY_CODES_VERIFY_ENABLED", "true");
        // OAuth 2.1 authorization server: /oauth/** and /admin/oauth/**
        env.put("GOTRUE_OAUTH_SERVER_ENABLED", "true");
        env.put("GOTRUE_OAUTH_SERVER_ALLOW_DYNAMIC_REGISTRATION", "true");
        env.put("GOTRUE_OAUTH_SERVER_AUTHORIZATION_PATH", OAUTH_AUTHORIZATION_PATH);
        // SAML SSO: /sso, /saml/** and /admin/sso/**. The signing key is generated per JVM.
        env.put("GOTRUE_SAML_ENABLED", "true");
        env.put("GOTRUE_SAML_PRIVATE_KEY", generateSamlPrivateKey());
        return env;
    }

    private static synchronized void start() {
        if (!SUPABASE_AUTH.isRunning()) {
            SUPABASE_AUTH.start();
        }
    }

    /**
     * Docker network shared by the Supabase containers, so that other services such as Storage can reach the
     * PostgreSQL container by its alias.
     */
    public static Network network() {
        return NETWORK;
    }

    /**
     * Starts PostgreSQL if needed and returns its container. Other Supabase services run against the same
     * database, each in its own schema, as in a Supabase project.
     */
    public static synchronized GenericContainer<?> postgres() {
        if (!POSTGRES.isRunning()) {
            POSTGRES.start();
        }
        return POSTGRES;
    }

    /**
     * Connection URL of the shared PostgreSQL container as seen from the Docker network.
     */
    public static String postgresNetworkUrl() {
        return "postgres://postgres:" + POSTGRES_PASSWORD + "@" + POSTGRES_ALIAS + ":" + POSTGRES_PORT + "/postgres";
    }

    /**
     * Mints an HS256 JWT with the {@code anon} role, signed with the shared JWT secret. This is the legacy anon
     * key format, which Storage treats as an anonymous caller subject to Row Level Security.
     */
    public static String anonJwt() {
        return roleJwt("anon");
    }

    public static String baseUrl() {
        start();
        return HTTP + SUPABASE_AUTH.getHost() + ":" + SUPABASE_AUTH.getMappedPort(SUPABASE_AUTH_PORT);
    }

    /**
     * {@code GOTRUE_JWT_SECRET}: the HS256 secret the container signs access tokens with. Not a real secret.
     */
    public static String jwtSecret() {
        return JWT_SECRET;
    }

    public static Map<String, String> getProperties() {
        String baseUrl = baseUrl();
        return Map.of(
            SUPABASE_URL_PROPERTY, baseUrl,
            "micronaut.security.token.jwt.signatures.jwks.supabase.url", baseUrl + "/auth/v1/.well-known/jwks.json",
            "micronaut.http.services.supabase.url", baseUrl,
            // GoTrue answers several routes with redirects to GOTRUE_SITE_URL, which nothing serves in tests.
            "micronaut.http.services.supabase.follow-redirects", "false",
            // The container is a bare GoTrue server without the Supabase gateway: the API lives at its root.
            SupabaseConfiguration.AUTH_PATH_PROPERTY, "",
            PUBLISHABLE_KEY_PROPERTY, PUBLISHABLE_KEY,
            // Direct GoTrue has no API gateway: admin routes need a legacy service-role JWT as the secret key.
            SECRET_KEY_PROPERTY, serviceRoleJwt());
    }

    /**
     * Mints an HS256 JWT with the {@code service_role} role, signed with {@code GOTRUE_JWT_SECRET}. This is the
     * legacy service-role key format; GoTrue accepts it as admin credentials for {@code /admin/**} and {@code /invite}.
     */
    public static String serviceRoleJwt() {
        return roleJwt(SERVICE_ROLE);
    }

    private static String roleJwt(String role) {
        long now = Instant.now().getEpochSecond();
        String header = base64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = base64Url(("{\"role\":\"" + role + "\",\"iss\":\"supabase\",\"iat\":" + now
            + ",\"exp\":" + (now + 3600) + "}").getBytes(StandardCharsets.UTF_8));
        String signingInput = header + "." + payload;
        byte[] signature = hmac("HmacSHA256", JWT_SECRET.getBytes(StandardCharsets.UTF_8),
            signingInput.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + base64Url(signature);
    }

    /**
     * Computes the current RFC 6238 TOTP code (SHA1, 30 second period, 6 digits) for a base32 secret
     * as returned by {@code POST /factors} for a {@code totp} factor.
     */
    static String totpCode(String base32Secret) {
        return totpCode(base32Secret, Instant.now().getEpochSecond() / 30);
    }

    static String totpCode(String base32Secret, long counter) {
        byte[] key = base32Decode(base32Secret);
        byte[] message = ByteBuffer.allocate(Long.BYTES).putLong(counter).array();
        byte[] hash = hmac("HmacSHA1", key, message);
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
            | ((hash[offset + 1] & 0xFF) << 16)
            | ((hash[offset + 2] & 0xFF) << 8)
            | (hash[offset + 3] & 0xFF);
        return String.format(Locale.ROOT, "%06d", binary % 1_000_000);
    }

    /**
     * Minimal SAML 2.0 identity provider metadata accepted by {@code POST /admin/sso/providers}.
     * It carries no signing certificate because the tests never complete a SAML login.
     *
     * @param entityId Entity id of the identity provider, an absolute {@code https} URL
     */
    static String samlIdpMetadata(String entityId) {
        return """
            <?xml version="1.0" encoding="UTF-8"?>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s/sso"/>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s/sso"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>
            """.formatted(entityId, entityId, entityId);
    }

    private static byte[] hmac(String algorithm, byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(message);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] base32Decode(String encoded) {
        String normalized = encoded.replace("=", "").toUpperCase(Locale.ROOT);
        byte[] out = new byte[normalized.length() * 5 / 8];
        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;
        for (char c : normalized.toCharArray()) {
            int value = BASE32_ALPHABET.indexOf(c);
            if (value < 0) {
                throw new IllegalArgumentException("Not a base32 character: " + c);
            }
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out[index++] = (byte) (buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }
        return out;
    }

    /**
     * {@code GOTRUE_SAML_PRIVATE_KEY} must be a base64 encoded PKCS#1 ({@code RSAPrivateKey}) DER structure.
     * The JDK only emits PKCS#8, which wraps PKCS#1 in an {@code OCTET STRING}; this unwraps it.
     */
    private static String generateSamlPrivateKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            return Base64.getEncoder().encodeToString(pkcs8ToPkcs1(keyPair.getPrivate().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * PKCS#8: {@code SEQUENCE { INTEGER version, SEQUENCE algorithm, OCTET STRING privateKey }}.
     * Returns the content of the {@code OCTET STRING}, which is the PKCS#1 {@code RSAPrivateKey}.
     */
    static byte[] pkcs8ToPkcs1(byte[] pkcs8) {
        int[] position = {0};
        expectTag(pkcs8, position, 0x30);
        readLength(pkcs8, position);
        expectTag(pkcs8, position, 0x02);
        skip(pkcs8, position);
        expectTag(pkcs8, position, 0x30);
        skip(pkcs8, position);
        expectTag(pkcs8, position, 0x04);
        int length = readLength(pkcs8, position);
        return Arrays.copyOfRange(pkcs8, position[0], position[0] + length);
    }

    private static void skip(byte[] der, int[] position) {
        int length = readLength(der, position);
        position[0] += length;
    }

    private static void expectTag(byte[] der, int[] position, int tag) {
        int actual = der[position[0]++] & 0xFF;
        if (actual != tag) {
            throw new IllegalArgumentException("Expected DER tag 0x" + Integer.toHexString(tag)
                + " but found 0x" + Integer.toHexString(actual));
        }
    }

    private static int readLength(byte[] der, int[] position) {
        int first = der[position[0]++] & 0xFF;
        if (first < 0x80) {
            return first;
        }
        int numBytes = first & 0x7F;
        int length = 0;
        for (int i = 0; i < numBytes; i++) {
            length = (length << 8) | (der[position[0]++] & 0xFF);
        }
        return length;
    }
}

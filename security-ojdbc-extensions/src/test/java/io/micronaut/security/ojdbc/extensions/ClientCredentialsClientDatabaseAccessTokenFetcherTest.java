package io.micronaut.security.ojdbc.extensions;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.generator.TokenGenerator;
import oracle.jdbc.spi.OracleResourceProvider;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.CLIENT_ID_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.CLIENT_SECRET_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.SCOPE_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.TOKEN_URL_PARAMETER;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientCredentialsClientDatabaseAccessTokenFetcherTest {

    private static final String SPEC_NAME = "ClientCredentialsClientDatabaseAccessTokenFetcherTest";
    private static final int VALID_TOKEN_EXPIRATION_SECONDS = 3600;
    private static final int EXPIRED_TOKEN_EXPIRATION_SECONDS = -3600;
    private static final AtomicInteger TOKEN_REQUEST_COUNT = new AtomicInteger();
    private static final AtomicReference<TokenRequest> TOKEN_REQUEST = new AtomicReference<>();

    private static final DatabaseAccessTokenFetcher FETCHER = new ClientCredentialsClientDatabaseAccessTokenFetcher();

    @Test
    void fetchDatabaseAccessTokenPostsClientCredentialsAndReturnsAccessToken() {
        TOKEN_REQUEST.set(null);

        withMockAuthorizationServer(server -> {
            String tokenUrl = tokenUrl(server, "token");
            Map<OracleResourceProvider.Parameter, CharSequence> parameters = parameters(tokenUrl);
            parameters.put(SCOPE_PARAMETER, "https://database.example/.default");

            String token = FETCHER.fetchDatabaseAccessToken(parameters);

            JWT jwt = assertDoesNotThrow(() -> JWTParser.parse(token));
            assertInstanceOf(SignedJWT.class, jwt);
            TokenRequest request = TOKEN_REQUEST.get();
            assertNotNull(request);
            assertEquals(MediaType.APPLICATION_JSON, request.accept());
            assertEquals(MediaType.APPLICATION_FORM_URLENCODED, request.contentType());
            assertEquals(Map.of(
                    "grant_type", "client_credentials",
                    "client_id", "database-client",
                    "client_secret", "database secret",
                    "scope", "https://database.example/.default"), request.formFields());
        });
    }

    @Test
    void fetchDatabaseAccessTokenOmitsScopeWhenParameterIsAbsent() {
        TOKEN_REQUEST.set(null);

        withMockAuthorizationServer(server -> {
            String tokenUrl = tokenUrl(server, "token");

            String token = FETCHER.fetchDatabaseAccessToken(parameters(tokenUrl));

            JWT jwt = assertDoesNotThrow(() -> JWTParser.parse(token));
            assertInstanceOf(SignedJWT.class, jwt);
            TokenRequest request = TOKEN_REQUEST.get();
            assertNotNull(request);
            assertEquals(Map.of(
                    "grant_type", "client_credentials",
                    "client_id", "database-client",
                    "client_secret", "database secret"), request.formFields());
        });
    }

    @Test
    void fetchDatabaseAccessTokenReusesCachedAccessTokenForSameParameters() {
        TOKEN_REQUEST.set(null);
        TOKEN_REQUEST_COUNT.set(0);

        withMockAuthorizationServer(server -> {
            String tokenUrl = tokenUrl(server, "token");
            Map<OracleResourceProvider.Parameter, CharSequence> parameters = parameters(tokenUrl);
            parameters.put(SCOPE_PARAMETER, "https://database.example/.default");
            DatabaseAccessTokenFetcher fetcher = new ClientCredentialsClientDatabaseAccessTokenFetcher();
            assertEquals(0, TOKEN_REQUEST_COUNT.get());

            String token = fetcher.fetchDatabaseAccessToken(parameters);
            JWT jwt = assertDoesNotThrow(() -> JWTParser.parse(token));
            assertInstanceOf(SignedJWT.class, jwt);
            assertEquals(1, TOKEN_REQUEST_COUNT.get());

            String newToken = fetcher.fetchDatabaseAccessToken(parameters);
            assertEquals(token, newToken);

            assertEquals(1, TOKEN_REQUEST_COUNT.get());
            TokenRequest request = TOKEN_REQUEST.get();
            assertNotNull(request);
            assertEquals(Map.of(
                    "grant_type", "client_credentials",
                    "client_id", "database-client",
                    "client_secret", "database secret",
                    "scope", "https://database.example/.default"), request.formFields());
        });
    }

    @Test
    void fetchDatabaseAccessTokenFetchesNewAccessTokenWhenCachedTokenIsExpired() {
        TOKEN_REQUEST.set(null);
        TOKEN_REQUEST_COUNT.set(0);

        withMockAuthorizationServer(server -> {
            String tokenUrl = tokenUrl(server, "token/expired-once");
            Map<OracleResourceProvider.Parameter, CharSequence> parameters = parameters(tokenUrl);
            parameters.put(SCOPE_PARAMETER, "https://database.example/.default");
            DatabaseAccessTokenFetcher fetcher = new ClientCredentialsClientDatabaseAccessTokenFetcher();

            String token = fetcher.fetchDatabaseAccessToken(parameters);
            JWT jwt = assertDoesNotThrow(() -> JWTParser.parse(token));
            assertInstanceOf(SignedJWT.class, jwt);
            assertEquals(2, TOKEN_REQUEST_COUNT.get());

            String cachedToken = fetcher.fetchDatabaseAccessToken(parameters);
            assertEquals(token, cachedToken);
            assertEquals(2, TOKEN_REQUEST_COUNT.get());
        });
    }

    @Test
    void fetchDatabaseAccessTokenRequiresProviderParameters() {
        DatabaseAccessTokenFetcherException missingTokenUrl = assertThrows(DatabaseAccessTokenFetcherException.class,
                () -> FETCHER.fetchDatabaseAccessToken(Map.of()));
        assertEquals("Missing required provider parameter: tokenUrl", missingTokenUrl.getMessage());
        assertInstanceOf(IllegalStateException.class, missingTokenUrl.getCause());

        DatabaseAccessTokenFetcherException missingClientId = assertThrows(DatabaseAccessTokenFetcherException.class,
                () -> FETCHER.fetchDatabaseAccessToken(Map.of(TOKEN_URL_PARAMETER, "http://localhost/token")));
        assertEquals("Missing required provider parameter: clientId", missingClientId.getMessage());
        assertInstanceOf(IllegalStateException.class, missingClientId.getCause());
    }

    @Test
    void fetchDatabaseAccessTokenThrowsForNonSuccessStatus() {
        withMockAuthorizationServer(server -> {
            String tokenUrl = tokenUrl(server, "token/error");

            DatabaseAccessTokenFetcherException exception = assertThrows(DatabaseAccessTokenFetcherException.class,
                    () -> FETCHER.fetchDatabaseAccessToken(parameters(tokenUrl)));

            assertTrue(exception.getMessage().startsWith("Token endpoint returned HTTP status 401: "));
            assertTrue(exception.getMessage().contains("invalid_client"));
        });
    }

    @Test
    void fetchDatabaseAccessTokenThrowsWhenAccessTokenIsMissing() {
        withMockAuthorizationServer(server -> {
            String tokenUrl = tokenUrl(server, "token/missing-access-token");

            DatabaseAccessTokenFetcherException exception = assertThrows(DatabaseAccessTokenFetcherException.class,
                    () -> FETCHER.fetchDatabaseAccessToken(parameters(tokenUrl)));

            assertEquals("Failed to request database access token", exception.getMessage());
            assertNotNull(exception.getCause());
        });
    }

    @Test
    void fetchDatabaseAccessTokenRejectsNonObjectTokenResponse() {
        withMockAuthorizationServer(server -> {
            String tokenUrl = tokenUrl(server, "token/not-object");

            DatabaseAccessTokenFetcherException exception = assertThrows(DatabaseAccessTokenFetcherException.class,
                    () -> FETCHER.fetchDatabaseAccessToken(parameters(tokenUrl)));

            assertEquals("Failed to request database access token", exception.getMessage());
            assertNotNull(exception.getCause());
        });
    }

    @Test
    void fetchDatabaseAccessTokenWrapsIoException() throws IOException {
        int port = unusedPort();
        String tokenUrl = "http://127.0.0.1:" + port + "/token";

        DatabaseAccessTokenFetcherException exception = assertThrows(DatabaseAccessTokenFetcherException.class,
                () -> FETCHER.fetchDatabaseAccessToken(parameters(tokenUrl)));

        assertEquals("Failed to request database access token", exception.getMessage());
        assertNotNull(exception.getCause());
    }

    @Test
    void fetchDatabaseAccessTokenWrapsInterruptedExceptionAndRestoresInterruptStatus() throws Exception {
        withMockAuthorizationServer(server -> {
            String tokenUrl = tokenUrl(server, "token");
            ExecutorService executorService = Executors.newSingleThreadExecutor();
            try {
                Future<InterruptedFetchResult> result = executorService.submit(() -> {
                    Thread.currentThread().interrupt();
                    try {
                        FETCHER.fetchDatabaseAccessToken(parameters(tokenUrl));
                        return new InterruptedFetchResult(null, Thread.currentThread().isInterrupted());
                    } catch (DatabaseAccessTokenFetcherException e) {
                        boolean interrupted = Thread.currentThread().isInterrupted();
                        Thread.interrupted();
                        return new InterruptedFetchResult(e, interrupted);
                    }
                });

                try {
                    InterruptedFetchResult interruptedFetchResult = result.get(5, TimeUnit.SECONDS);
                    assertNotNull(interruptedFetchResult.exception());
                    assertEquals("Interrupted while requesting database access token",
                            interruptedFetchResult.exception().getMessage());
                    assertTrue(interruptedFetchResult.interrupted());
                } catch (Exception e) {
                    throw new AssertionError(e);
                }
            } finally {
                executorService.shutdownNow();
            }
        });
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class OauthController {
        private final TokenGenerator tokenGenerator;

        OauthController(TokenGenerator tokenGenerator) {
            this.tokenGenerator = tokenGenerator;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Produces(MediaType.APPLICATION_JSON)
        @Post("/token")
        HttpResponse<Map<String, Object>> token(@Body Map<String, String> body, HttpRequest<?> request) {
            TOKEN_REQUEST.set(tokenRequest(body, request));
            return tokenResponse(VALID_TOKEN_EXPIRATION_SECONDS);
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Produces(MediaType.APPLICATION_JSON)
        @Post("/token/expired-once")
        HttpResponse<Map<String, Object>> expiredOnce(@Body Map<String, String> body, HttpRequest<?> request) {
            TOKEN_REQUEST.set(tokenRequest(body, request));
            return TOKEN_REQUEST_COUNT.get() == 1
                    ? tokenResponse(EXPIRED_TOKEN_EXPIRATION_SECONDS)
                    : tokenResponse(VALID_TOKEN_EXPIRATION_SECONDS);
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Produces(MediaType.APPLICATION_JSON)
        @Post("/token/error")
        HttpResponse<Map<String, Object>> error(@Body Map<String, String> body, HttpRequest<?> request) {
            TOKEN_REQUEST.set(tokenRequest(body, request));
            return HttpResponse.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "invalid_client"));
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Produces(MediaType.APPLICATION_JSON)
        @Post("/token/missing-access-token")
        HttpResponse<Map<String, Object>> missingAccessToken(@Body Map<String, String> body, HttpRequest<?> request) {
            TOKEN_REQUEST.set(tokenRequest(body, request));
            return HttpResponse.ok(Map.of(
                    "token_type", "Bearer",
                    "expires_in", 3600));
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Produces(MediaType.APPLICATION_JSON)
        @Post("/token/not-object")
        HttpResponse<String> notObject(@Body Map<String, String> body, HttpRequest<?> request) {
            TOKEN_REQUEST.set(tokenRequest(body, request));
            return HttpResponse.ok("[\"not-object\"]");
        }

        private HttpResponse<Map<String, Object>> tokenResponse(int expirationSeconds) {
            return HttpResponse.ok(Map.of(
                    "access_token", tokenGenerator.generateToken(Authentication.build("sergio"), expirationSeconds).orElseThrow(),
                    "token_type", "Bearer",
                    "expires_in", 3600));
        }
    }

    private record TokenRequest(String accept, String contentType, Map<String, String> formFields) {
    }

    private record InterruptedFetchResult(DatabaseAccessTokenFetcherException exception, boolean interrupted) {
    }

    private static TokenRequest tokenRequest(Map<String, String> body, HttpRequest<?> request) {
        TOKEN_REQUEST_COUNT.incrementAndGet();
        return new TokenRequest(
                request.getHeaders().get(HttpHeaders.ACCEPT),
                request.getHeaders().get(HttpHeaders.CONTENT_TYPE),
                body);
    }

    private static Map<OracleResourceProvider.Parameter, CharSequence> parameters(String tokenUrl) {
        Map<OracleResourceProvider.Parameter, CharSequence> parameters = new LinkedHashMap<>();
        parameters.put(TOKEN_URL_PARAMETER, tokenUrl);
        parameters.put(CLIENT_ID_PARAMETER, "database-client");
        parameters.put(CLIENT_SECRET_PARAMETER, "database secret");
        return parameters;
    }

    private static void withMockAuthorizationServer(ServerCallback callback) {
        Map<String, Object> configuration = Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.server.port", -1,
                "datasources.default.enabled", false,
                "micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne");
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration)) {
            callback.accept(server);
        }
    }

    private static String tokenUrl(EmbeddedServer server, String path) {
        return UriBuilder.of(server.getURI()).path(path).build().toString();
    }

    private static int unusedPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    @FunctionalInterface
    private interface ServerCallback {
        void accept(EmbeddedServer server);
    }
}

package io.micronaut.security.oauth2.endpoint.userinfo;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator;
import jakarta.inject.Singleton;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A JWT accepted by the JWT token validator must not be forwarded to the UserInfo endpoint of an OpenID provider,
 * which would otherwise receive live access tokens issued by an unrelated authorization server.
 */
class UserInfoClientTokenValidatorAcceptedJwtNotForwardedTest {

    enum Scenario {
        /**
         * The application trusts an unrelated authorization server via {@code micronaut.security.token.jwt.signatures.jwks.*}.
         * Signature verification against a remote JWKS is asynchronous.
         */
        JWKS,
        /**
         * The application issues its own JWTs and runs the JWT validator on the blocking executor.
         */
        SECRET_ON_BLOCKING_EXECUTOR,
        /**
         * The application issues its own JWTs and validates them synchronously.
         */
        SECRET
    }

    @ParameterizedTest
    @EnumSource(Scenario.class)
    void jwtAcceptedByJwtValidatorIsNotSentToUserInfoEndpoint(Scenario scenario) throws Exception {
        try (EmbeddedServer unrelatedAuthServer = ApplicationContext.run(EmbeddedServer.class,
            Map.of("spec.name", "UserInfoClientTokenValidatorAcceptedJwtNotForwardedTestUnrelatedAuthServer"));
             EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class,
                 Map.of("spec.name", "UserInfoClientTokenValidatorAcceptedJwtNotForwardedTestAuthServer"))) {
            OpenIdAutoConfigurationController metadata = authServer.getApplicationContext().getBean(OpenIdAutoConfigurationController.class);
            metadata.setUrl(authServer.getURL().toString());
            UserInfoController userInfo = authServer.getApplicationContext().getBean(UserInfoController.class);
            UnrelatedAuthServerKeys unrelatedKeys = unrelatedAuthServer.getApplicationContext().getBean(UnrelatedAuthServerKeys.class);

            Map<String, Object> serverConfig = new HashMap<>(Map.of(
                "spec.name", "UserInfoClientTokenValidatorAcceptedJwtNotForwardedTest",
                "micronaut.security.oauth2.userinfo.validator", "true",
                "micronaut.security.oauth2.clients.authserver.client-id", "test-client-id-fixture",
                "micronaut.security.oauth2.clients.authserver.client-secret", "test-client-secret-fixture-not-a-secret",
                "micronaut.security.oauth2.clients.authserver.openid.issuer", authServer.getURL().toString()
            ));
            switch (scenario) {
                case JWKS -> serverConfig.put("micronaut.security.token.jwt.signatures.jwks.unrelated.url", unrelatedAuthServer.getURL() + "/keys");
                case SECRET_ON_BLOCKING_EXECUTOR -> {
                    serverConfig.put("micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne-test-fixture-not-a-secret");
                    serverConfig.put("micronaut.security.token.jwt.nimbus.reactive-validator-execute-on-blocking", "true");
                }
                case SECRET -> serverConfig.put("micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne-test-fixture-not-a-secret");
            }
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, serverConfig)) {
                assertEquals(1, server.getApplicationContext().getBeansOfType(UserInfoClientTokenValidator.class).size());
                String jwt = scenario == Scenario.JWKS
                    ? unrelatedKeys.sign(unrelatedAuthServer.getURL().toString())
                    : server.getApplicationContext().getBean(JwtTokenGenerator.class).generateToken(Authentication.build("sherlock"), 3600).orElseThrow();

                try (HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                    BlockingHttpClient client = httpClient.toBlocking();

                    String username = assertDoesNotThrow(() -> client.retrieve(HttpRequest.GET("/principal")
                        .bearerAuth(jwt)
                        .accept(MediaType.TEXT_PLAIN)));
                    assertEquals("sherlock", username);
                    waitForUserInfoRequests(userInfo, 1);
                    assertTrue(userInfo.receivedTokens.isEmpty(),
                        "an already accepted JWT was forwarded to the UserInfo endpoint: " + userInfo.receivedTokens.size() + " request(s)");

                    HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
                        () -> client.retrieve(HttpRequest.GET("/principal").bearerAuth("opaque-token-fixture").accept(MediaType.TEXT_PLAIN)));
                    assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
                    waitForUserInfoRequests(userInfo, 1);
                    assertEquals(List.of("Bearer opaque-token-fixture"), userInfo.receivedTokens,
                        "a token rejected by the JWT validator is still validated against the UserInfo endpoint");
                }
            }
        }
    }

    /**
     * The UserInfo request, if any, is issued asynchronously and may still be in flight when the response is received.
     */
    private static void waitForUserInfoRequests(UserInfoController userInfo, int expected) {
        long deadline = System.currentTimeMillis() + 2_000;
        while (userInfo.receivedTokens.size() < expected && System.currentTimeMillis() < deadline) {
            Thread.onSpinWait();
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorAcceptedJwtNotForwardedTest")
    @Controller("/principal")
    static class EchoUserController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        @Produces(MediaType.TEXT_PLAIN)
        String index(Principal principal) {
            return principal.getName();
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorAcceptedJwtNotForwardedTestUnrelatedAuthServer")
    @Singleton
    static class UnrelatedAuthServerKeys {
        private final RSAKey rsaKey;

        UnrelatedAuthServerKeys() throws JOSEException {
            this.rsaKey = new RSAKeyGenerator(2048)
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("unrelated-test-fixture")
                .generate();
        }

        String jwks() {
            return new JWKSet(rsaKey.toPublicJWK()).toString();
        }

        String sign(String issuer) throws JOSEException {
            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                new JWTClaimsSet.Builder()
                    .subject("sherlock")
                    .issuer(issuer)
                    .expirationTime(new Date(System.currentTimeMillis() + 3_600_000L))
                    .build());
            signedJWT.sign(new RSASSASigner(rsaKey));
            return signedJWT.serialize();
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorAcceptedJwtNotForwardedTestUnrelatedAuthServer")
    @Controller("/keys")
    static class UnrelatedAuthServerKeysController {
        private final UnrelatedAuthServerKeys keys;

        UnrelatedAuthServerKeysController(UnrelatedAuthServerKeys keys) {
            this.keys = keys;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        @Produces(MediaType.APPLICATION_JSON)
        String keys() {
            return keys.jwks();
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorAcceptedJwtNotForwardedTestAuthServer")
    @Controller
    static class UserInfoController {
        final List<String> receivedTokens = new CopyOnWriteArrayList<>();

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/userinfo")
        HttpResponse<?> info(@Header String authorization) {
            receivedTokens.add(authorization);
            return HttpResponse.unauthorized();
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorAcceptedJwtNotForwardedTestAuthServer")
    @Controller
    static class OpenIdAutoConfigurationController {
        private String url;

        void setUrl(String url) {
            this.url = url;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        String index() {
            return """
                {
                    "issuer":"%s/",
                    "authorization_endpoint":"%s/authorize",
                    "token_endpoint":"%s/oauth/token",
                    "userinfo_endpoint":"%s/userinfo",
                    "jwks_uri":"%s/.well-known/jwks.json",
                    "response_types_supported":["code"],
                    "subject_types_supported":["public"],
                    "id_token_signing_alg_values_supported":["RS256"]
                }
                """.replace("%s", url);
        }
    }
}

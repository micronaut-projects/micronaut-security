package io.micronaut.security.test;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.JWKGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.NoSuchBeanException;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.json.JsonMapper;
import io.micronaut.runtime.context.scope.Refreshable;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.security.token.claims.ClaimsGenerator;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.security.token.jwt.endpoints.JwkProvider;
import io.micronaut.security.token.jwt.endpoints.KeysController;
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator;
import io.micronaut.security.token.jwt.signature.jwks.CacheableJwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.ReactorCacheJwkSetFetcher;
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGenerator;
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration;
import io.micronaut.security.token.render.BearerAccessRefreshToken;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;

import static java.lang.Thread.sleep;
import static org.junit.jupiter.api.Assertions.*;

class JwksCacheTest  {

    Map<String, Object> authServerConfig = Map.of(
            "micronaut.http.client.read-timeout","30s",
            "micronaut.security.authentication", "bearer"
            );

    Map<String, Object> googleConfig = Map.of(
            "micronaut.http.client.read-timeout","30s",
            "micronaut.security.authentication", "bearer",
            "spec.name", "GoogleJwksCacheSpec",
            "endpoints.refresh.enabled", StringUtils.TRUE,
            "endpoints.refresh.sensitive", StringUtils.FALSE
    );

    Map<String, Object> cognitoConfig = Map.of(
            "micronaut.http.client.read-timeout","30s",
            "micronaut.security.authentication", "bearer",
            "spec.name", "CognitoJwksCacheSpec",
            "endpoints.refresh.enabled", StringUtils.TRUE,
            "endpoints.refresh.sensitive", StringUtils.FALSE
    );
    Map<String, Object> appleConfig = Map.of(
            "micronaut.http.client.read-timeout","30s",
            "micronaut.security.authentication", "bearer",
            "spec.name", "AppleJwksCacheSpec"
    );


    private void hello(BlockingHttpClient client, String token, boolean doAssertion) {
        HttpRequest<?> request = HttpRequest.GET("/hello").bearerAuth(token);
        if (doAssertion) {
            String response = client.retrieve(request);
            assertEquals("Hello World", response);
        } else {
            try {
                client.retrieve(request);
            } catch(HttpClientResponseException e) {
                assertTrue(true); // token is not valid for cached JWKS
            }
        }
    }

    @Test
    void jwkAreCached() throws ParseException, InterruptedException, JOSEException {
        EmbeddedServer googleEmbeddedServer = ApplicationContext.run(EmbeddedServer.class, googleConfig);
        EmbeddedServer cognitoEmbeddedServer = ApplicationContext.run(EmbeddedServer.class, cognitoConfig);
        EmbeddedServer appleEmbeddedServer = ApplicationContext.run(EmbeddedServer.class, appleConfig);
        Map<String, Object> embeddedServerConfig = Map.of(
                "micronaut.http.client.read-timeout","30s",
                "micronaut.caches.jwks.expire-after-write","5s",
                "micronaut.security.token.jwt.signatures.jwks.apple.url","http://localhost:" + appleEmbeddedServer.getPort() + "/keys",
                "micronaut.security.token.jwt.signatures.jwks.google.url","http://localhost:" + googleEmbeddedServer.getPort() + "/keys",
                "micronaut.security.token.jwt.signatures.jwks.cognito.url","http://localhost:" + cognitoEmbeddedServer.getPort() + "/keys",
                "spec.name", "JwksCacheSpec"
        );
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer.class, embeddedServerConfig);

        HttpClient googleHttpClient = embeddedServer.getApplicationContext().createBean(HttpClient.class, googleEmbeddedServer.getURL());
        BlockingHttpClient googleClient = googleHttpClient.toBlocking();

        HttpClient appleHttpClient = embeddedServer.getApplicationContext().createBean(HttpClient.class, appleEmbeddedServer.getURL());
        BlockingHttpClient appleClient = appleHttpClient.toBlocking();

        HttpClient cognitoHttpClient = embeddedServer.getApplicationContext().createBean(HttpClient.class, cognitoEmbeddedServer.getURL());
        BlockingHttpClient cognitoClient = cognitoHttpClient.toBlocking();

        HttpClient httpClient = embeddedServer.getApplicationContext().createBean(HttpClient.class, embeddedServer.getURL());
        BlockingHttpClient client = httpClient.toBlocking();

        assertEquals(0, totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer));
        assertFalse(embeddedServer.getApplicationContext().containsBean(ReactorCacheJwkSetFetcher.class));
        assertThrows(NoSuchBeanException.class, () -> embeddedServer.getApplicationContext().getBean(ReactorCacheJwkSetFetcher.class));
        assertDoesNotThrow(() -> embeddedServer.getApplicationContext().getBean(CacheableJwkSetFetcher.class));
        BearerAccessRefreshToken googleBearerAccessRefreshToken = assertDoesNotThrow(() -> login(googleClient));
        assertNotNull(googleBearerAccessRefreshToken.getAccessToken());

        String googleAccessToken = googleBearerAccessRefreshToken.getAccessToken();
        JWT googleJWT = JWTParser.parse(googleAccessToken);
        BearerAccessRefreshToken appleBearerAccessRefreshToken = login(appleClient);
        String appleAccessToken = appleBearerAccessRefreshToken.getAccessToken();
        JWT appleJWT = JWTParser.parse(appleAccessToken);
        BearerAccessRefreshToken cognitoBearerAccessRefreshToken = login(cognitoClient);
        String cognitoAccessToken = cognitoBearerAccessRefreshToken.getAccessToken();
        JWT cognitoJWT = JWTParser.parse(cognitoAccessToken);

        assertKeyId(googleJWT, "google");
        assertKeyId(appleJWT, "apple");
        assertNotNull(appleBearerAccessRefreshToken.getAccessToken());
        assertKeyId(cognitoJWT, "cognito");
        assertNotNull(cognitoBearerAccessRefreshToken.getAccessToken());

        assertEquals(0, totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer));

        //when:
        int oldInvocations = totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer);
        hello(client, googleAccessToken, true);
        hello(client, appleAccessToken, true);
        hello(client, cognitoAccessToken, true);

        // then:
        assertTrue(totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer) >= (oldInvocations + 3));

        //when: 'when you invoke it again all the keys are cached'
        oldInvocations = totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer);
        hello(client, appleAccessToken, true);

        //then:
        assertEquals(totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer), oldInvocations);

        //when: "generate new keys for cognito but with same id, other JWK sets do not match the ID, for cognito the verification key fails and a new one is fetched from the server"
        oldInvocations = totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer);
        int invocations = cognitoInvocations(cognitoEmbeddedServer);
        assertDoesNotThrow(() -> refresh(cognitoClient));
        cognitoEmbeddedServer.getApplicationContext().getBean(CognitoKeysController.class).invocations = invocations;
        cognitoAccessToken = loginAccessToken(cognitoClient);
        sleep(6_000); // sleep for six seconds so JWKS cache expires
        hello(client, cognitoAccessToken, true);

        //then:
        assertTrue(totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer) >= (oldInvocations + 1));

        //when: 'generate a new JWKS with new kid, JWKS attempt to refresh'
        oldInvocations = totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer);
        CognitoSignatureConfiguration cognitoSignatureConfiguration = cognitoEmbeddedServer.getApplicationContext().getBean(CognitoSignatureConfiguration.class);
        invocations = cognitoInvocations(cognitoEmbeddedServer);
        refresh(cognitoClient);
        cognitoEmbeddedServer.getApplicationContext().getBean(CognitoKeysController.class).invocations = invocations;
        cognitoSignatureConfiguration.rotateKid();
        cognitoAccessToken = loginAccessToken(cognitoClient);
        sleep(6_000); // sleep for six seconds so JWKS cache expires
        hello(client, cognitoAccessToken, true);

        //then:
        assertTrue(totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer) >= (oldInvocations + 1));

        //when: 'generate a new JWT without kid, JWKS attempt to refresh'
        oldInvocations = totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer);
        GoogleSignatureConfiguration googleSignatureConfiguration = googleEmbeddedServer.getApplicationContext().getBean(GoogleSignatureConfiguration.class);
        invocations = googleInvocations(googleEmbeddedServer);
        refresh(googleClient);
        googleEmbeddedServer.getApplicationContext().getBean(GoogleKeysController.class).invocations = invocations;
        googleSignatureConfiguration.clearKid();
        googleAccessToken = loginAccessToken(googleClient);
        sleep(6_000); // sleep for six seconds so JWKS cache expires
        hello(client, googleAccessToken, true);

        //then:
        assertTrue(totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer) >= (oldInvocations + 1));

        //when:
        oldInvocations = totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer);
        String randomSignedJwt = randomSignedJwt();
        hello(client, randomSignedJwt, false);

        //then:
        assertTrue(totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer) >= oldInvocations);

        //when:
        oldInvocations = totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer);
        sleep(6_000); // cache expires the token is still invalid but JWKS attempts to refresh
        hello(client, randomSignedJwt, false);

        //then:
        assertEquals(totalInvocations(appleEmbeddedServer, cognitoEmbeddedServer, googleEmbeddedServer), (oldInvocations + 3));

        //cleanup:
        googleEmbeddedServer.close();
        cognitoEmbeddedServer.close();
        appleEmbeddedServer.close();
        embeddedServer.close();
    }

    private int totalInvocations(EmbeddedServer appleServer, EmbeddedServer cognitoServer, EmbeddedServer googleServer) {
        return googleInvocations(googleServer) + appleInvocations(appleServer) + cognitoInvocations(cognitoServer);
    }

    private void assertKeyId(JWT jwt, String keyId) {
        assertTrue(jwt instanceof SignedJWT);
        assertEquals(((SignedJWT) jwt).getHeader().getKeyID(), keyId);
    }

    @Requires(property = "spec.name", value = "JwksCacheSpec")
    @Controller("/hello")
    static class HelloWorldController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        @Secured(SecurityRule.IS_AUTHENTICATED)
        String index() {
            return "Hello World";
        }
    }

    @Requires(property = "spec.name", value = "GoogleJwksCacheSpec")
    @Controller("/keys")
    @Replaces(KeysController.class)
    static class GoogleKeysController extends KeysController {
        int invocations = 0;
        GoogleKeysController(Collection<JwkProvider> jwkProviders, JsonMapper jsonMapper) {
            super(jwkProviders, jsonMapper);
        }
        @Get
        @SingleResult
        public Publisher<String> keys() {
            Publisher<String> result = super.keys();
            invocations++;
            return result;
        }
    }

    @Requires(property = "spec.name", value = "AppleJwksCacheSpec")
    @Controller("/keys")
    @Replaces(KeysController.class)
    static class AppleKeysController extends KeysController {
        int invocations = 0;
        AppleKeysController(Collection<JwkProvider> jwkProviders, JsonMapper jsonMapper) {
            super(jwkProviders, jsonMapper);
        }
        @Get
        @SingleResult
        public Publisher<String> keys() {
            Publisher<String> result = super.keys();
            invocations++;
            return result;
        }
    }

    @Requires(property = "spec.name", value = "CognitoJwksCacheSpec")
    @Controller("/keys")
    @Replaces(KeysController.class)
    static class CognitoKeysController extends KeysController {
        int invocations = 0;
        CognitoKeysController(Collection<JwkProvider> jwkProviders, JsonMapper jsonMapper) {
            super(jwkProviders, jsonMapper);
        }
        @Get
        @SingleResult
        public Publisher<String> keys() {
            Publisher<String> result = super.keys();
            invocations++;
            return result;
        }
    }

    @Singleton
    @Requires(property = "spec.name", value = "AppleJwksCacheSpec")
    static class AppleAuthenticationProvider extends MockAuthenticationProvider {
        AppleAuthenticationProvider() {
            super(List.of(new SuccessAuthenticationScenario("sherlock", Collections.emptyList())));
        }
    }

    @Singleton
    @Requires(property = "spec.name", value = "CognitoJwksCacheSpec")
    static class CognitoAuthenticationProvider extends MockAuthenticationProvider {
        CognitoAuthenticationProvider() {
            super( List.of(new SuccessAuthenticationScenario("sherlock", Collections.emptyList())));
        }
    }

    @Singleton
    @Requires(property = "spec.name", value = "GoogleJwksCacheSpec")
    static class GoogleAuthenticationProvider extends MockAuthenticationProvider {
        GoogleAuthenticationProvider() {
            super(List.of(new SuccessAuthenticationScenario("sherlock", Collections.emptyList())));
        }
    }

    @Requires(property = "spec.name", value = "AppleJwksCacheSpec")
    @Named("generator")
    @Singleton
    static class AppleSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        private List<JWK> jwks;
        private final static String KID = "apple";
        private RSAKey rsaKey;
        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256;
        AppleSignatureConfiguration() {
            refreshKey();
        }

        void refreshKey() {
            try {
                this.rsaKey = new RSAKeyGenerator(2048)
                        .algorithm(ALG)
                        .keyUse(KeyUse.SIGNATURE)
                        .keyID(KID)
                        .generate();
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }

            this.jwks = Collections.singletonList(rsaKey.toPublicJWK());
        }
        @Override
        public RSAPublicKey getPublicKey() {
            try {
                return rsaKey.toRSAPublicKey();
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }

        public RSAPrivateKey getPrivateKey() {
            try {
                return rsaKey.toRSAPrivateKey();
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public JWSAlgorithm getJwsAlgorithm() {
            return ALG;
        }

        @Override
        public List<JWK> retrieveJsonWebKeys() {
            return jwks;
        }
    }

    @Requires(property = "spec.name", value = "CognitoJwksCacheSpec")
    @Refreshable
    @Singleton
    @Replaces(TokenGenerator.class)
    static class JwtTokenGeneratorReplacement extends JwtTokenGenerator {
        JwtTokenGeneratorReplacement(CognitoSignatureConfiguration cognitoSignatureConfiguration,
                                     ClaimsGenerator claimsGenerator) {
            super(new RSASignatureGenerator(cognitoSignatureConfiguration), null, claimsGenerator);
        }
    }

    @Requires(property = "spec.name", value = "CognitoJwksCacheSpec")
    @Named("generator")
    @Refreshable
    @Singleton
    static class CognitoSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256;
        private List<JWK> jwks;
        private RSAKey rsaKey;
        String kid = "cognito";

        CognitoSignatureConfiguration() {
            this.rsaKey = null;
            this.jwks = null;
        }

        void rotateKid() {
            this.kid = "cognito-" + UUID.randomUUID().toString().substring(0, 5);
        }

        void clearKid() {
            this.kid = null;
        }

        List<JWK> getJwks() {
            if (jwks == null) {
                this.jwks = Collections.singletonList(rsaKey.toPublicJWK());
            }
            return jwks;
        }

        RSAKey getRsaKey() {
            if (rsaKey == null) {
                JWKGenerator jwkGenerator = new RSAKeyGenerator(2048)
                        .algorithm(ALG)
                        .keyUse(KeyUse.SIGNATURE);
                if (kid != null) {
                    jwkGenerator = jwkGenerator.keyID(kid);
                }
                try {
                    this.rsaKey = (RSAKey) jwkGenerator.generate();
                } catch (JOSEException e) {
                    throw new RuntimeException(e);
                }
            }
            return rsaKey;
        }

        @Override
        public RSAPublicKey getPublicKey() {
            try {
                return getRsaKey().toRSAPublicKey();
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public RSAPrivateKey getPrivateKey() {
            try {
                return getRsaKey().toRSAPrivateKey();
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public JWSAlgorithm getJwsAlgorithm() {
            return ALG;
        }

        @Override
        public List<JWK> retrieveJsonWebKeys() {
            return getJwks();
        }
    }

    @Requires(property = "spec.name", value = "GoogleJwksCacheSpec")
    @Refreshable
    @Singleton
    @Replaces(TokenGenerator.class)
    static class GoogleJwtTokenGeneratorReplacement extends JwtTokenGenerator {
        GoogleJwtTokenGeneratorReplacement(GoogleSignatureConfiguration googleSignatureConfiguration,
                                           ClaimsGenerator claimsGenerator) {
            super(new RSASignatureGenerator(googleSignatureConfiguration), null, claimsGenerator);
        }
    }

    @Requires(property = "spec.name", value = "GoogleJwksCacheSpec")
    @Named("generator")
    @Refreshable
    @Singleton
    static class GoogleSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256;
        private List<JWK> jwks;
        private RSAKey rsaKey;
        String kid = "google";

        GoogleSignatureConfiguration() {
            this.rsaKey = null;
            this.jwks = null;
        }

        void rotateKid() {
            this.kid = "google-" + UUID.randomUUID().toString().substring(0, 5);
        }

        void clearKid() {
            this.kid = null;
        }

        List<JWK> getJwks() {
            if (jwks == null) {
                this.jwks = Collections.singletonList(rsaKey.toPublicJWK());
            }
            return jwks;
        }

        RSAKey getRsaKey() {
            if (rsaKey == null) {
                JWKGenerator jwkGenerator = new RSAKeyGenerator(2048)
                        .algorithm(ALG)
                        .keyUse(KeyUse.SIGNATURE);
                if (kid != null) {
                    jwkGenerator = jwkGenerator.keyID(kid);
                }
                try {
                    this.rsaKey = (RSAKey) jwkGenerator.generate();
                } catch (JOSEException e) {
                    throw new RuntimeException(e);
                }
            }
            return rsaKey;
        }

        @Override
        public RSAPublicKey getPublicKey() {
            try {
                return getRsaKey().toRSAPublicKey();
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public RSAPrivateKey getPrivateKey() {
            try {
                return getRsaKey().toRSAPrivateKey();
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public JWSAlgorithm getJwsAlgorithm() {
            return ALG;
        }

        @Override
        public List<JWK> retrieveJsonWebKeys() {
            return getJwks();
        }
    }


    private int googleInvocations(EmbeddedServer server) {
        return server.getApplicationContext().getBean(GoogleKeysController.class).invocations;
    }

    private int appleInvocations(EmbeddedServer server) {
        return server.getApplicationContext().getBean(AppleKeysController.class).invocations;
    }

    private int cognitoInvocations(EmbeddedServer server) {
        return server.getApplicationContext().getBean(CognitoKeysController.class).invocations;
    }

    private static BearerAccessRefreshToken login(BlockingHttpClient client) {
        return client.retrieve(HttpRequest.POST("/login", Map.of("username", "sherlock", "password", "elementary")), BearerAccessRefreshToken.class);
    }

    private static String loginAccessToken(BlockingHttpClient client) {
        BearerAccessRefreshToken bearerAccessRefreshToken = login(client);
        assertNotNull(bearerAccessRefreshToken);
        assertNotNull(bearerAccessRefreshToken.getAccessToken());
        return bearerAccessRefreshToken.getAccessToken();
    }

    private static String randomSignedJwt() throws JOSEException {
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);
        JWSSigner signer = new MACSigner(sharedSecret);
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("{\"username\": \"sherlock\"}"));
        jwsObject.sign(signer);
        return jwsObject.serialize();
    }

    private static void refresh(BlockingHttpClient client) {
        HttpResponse<?> response = client.exchange(HttpRequest.POST("/refresh", "{\"force\": true}"));
        assertEquals(response.status(), HttpStatus.OK);
    }
}

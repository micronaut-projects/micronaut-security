package io.micronaut.security.token.jwt.signature.jwks;

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
import java.util.concurrent.atomic.AtomicInteger;

import static java.lang.Thread.sleep;
import static org.junit.jupiter.api.Assertions.*;

class JwksCacheTest  {

    private static Map<String, Object> config(String specName) {
        return  Map.of(
                "micronaut.http.client.read-timeout","30s",
                "micronaut.security.authentication", "bearer",
                "spec.name", specName,
                "endpoints.refresh.enabled", StringUtils.TRUE,
                "endpoints.refresh.sensitive", StringUtils.FALSE
        );
    }

    private static void hello(BlockingHttpClient client, String token) {
        assertEquals("Hello World", client.retrieve(HttpRequest.GET("/hello").bearerAuth(token)));
    }

    @Test
    void jwkAreCached() throws ParseException, InterruptedException, JOSEException {
        //given:
        // Start three servers which expose JSON Web Key Sets
        try (EmbeddedServer googleEmbeddedServer = ApplicationContext.run(EmbeddedServer.class, config("GoogleJwksCacheSpec"));
             EmbeddedServer cognitoEmbeddedServer = ApplicationContext.run(EmbeddedServer.class, config("CognitoJwksCacheSpec"));
             EmbeddedServer appleEmbeddedServer = ApplicationContext.run(EmbeddedServer.class, config("AppleJwksCacheSpec"));
             // Start another Micronaut application which configures the JSON Web Key Sets of the previous three servers
             EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer.class, Map.of(
                     "micronaut.http.client.read-timeout", "30s",
                     "micronaut.caches.jwks.expire-after-write", "5s",
                     "micronaut.security.token.jwt.signatures.jwks.apple.url", "http://localhost:" + appleEmbeddedServer.getPort() + "/keys",
                     "micronaut.security.token.jwt.signatures.jwks.google.url", "http://localhost:" + googleEmbeddedServer.getPort() + "/keys",
                     "micronaut.security.token.jwt.signatures.jwks.cognito.url", "http://localhost:" + cognitoEmbeddedServer.getPort() + "/keys",
                     "spec.name", "JwksCacheSpec"
             ));
             // Get HTTP Clients pointing to the three servers
             HttpClient googleHttpClient = embeddedServer.getApplicationContext().createBean(HttpClient.class, googleEmbeddedServer.getURL());
             HttpClient appleHttpClient = embeddedServer.getApplicationContext().createBean(HttpClient.class, appleEmbeddedServer.getURL());
             HttpClient cognitoHttpClient = embeddedServer.getApplicationContext().createBean(HttpClient.class, cognitoEmbeddedServer.getURL());
             // Get an HTTP Client pointing to the main Server
             HttpClient httpClient = embeddedServer.getApplicationContext().createBean(HttpClient.class, embeddedServer.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();
            AtomicInteger googleInvocations = googleEmbeddedServer.getApplicationContext().getBean(GoogleKeysController.class).invocations;
            AtomicInteger appleInvocations = appleEmbeddedServer.getApplicationContext().getBean(AppleKeysController.class).invocations;
            AtomicInteger cognitoInvocations = cognitoEmbeddedServer.getApplicationContext().getBean(CognitoKeysController.class).invocations;

            // Verify JWKS Caching is using Micronaut Cache not reactor caching
            assertFalse(embeddedServer.getApplicationContext().containsBean(ReactorCacheJwkSetFetcher.class));
            assertThrows(NoSuchBeanException.class, () -> embeddedServer.getApplicationContext().getBean(ReactorCacheJwkSetFetcher.class));
            assertDoesNotThrow(() -> embeddedServer.getApplicationContext().getBean(CacheableJwkSetFetcher.class));

            // Get an access Token for each of the three servers
            String googleAccessToken = loginAccessToken(googleHttpClient.toBlocking());
            assertKeyId(JWTParser.parse(googleAccessToken), "google");
            String appleAccessToken = loginAccessToken(appleHttpClient.toBlocking());
            assertKeyId(JWTParser.parse(appleAccessToken), "apple");
            String cognitoAccessToken = loginAccessToken(cognitoHttpClient.toBlocking());
            assertKeyId(JWTParser.parse(cognitoAccessToken), "cognito");

            // the servers keys endpoints have not been invoked yet
            assertEquals(0, googleInvocations.get());
            assertEquals(0, appleInvocations.get());
            assertEquals(0, cognitoInvocations.get());

            //when: 'a token is validated for the first time'
            hello(client, googleAccessToken);

            //then: 'the JWKS which verifies the token is fetched once'
            assertEquals(1, googleInvocations.get());

            // The JWKS of every provider are fetched concurrently, and the fetches still in flight when a JWKS
            // verifies the token are cancelled before their response is cached. Hence, the keys endpoints of Apple
            // and Cognito may be invoked more than once until a token signed with their keys is validated.

            //when: 'a token of each of the other providers is validated'
            hello(client, appleAccessToken);
            hello(client, cognitoAccessToken);

            //then: 'the JWKS of every provider has been fetched, and the cached Google JWKS was not fetched again'
            assertEquals(1, googleInvocations.get());
            assertTrue(appleInvocations.get() >= 1);
            assertTrue(cognitoInvocations.get() >= 1);

            //when: 'when you invoke it again all the keys are cached'
            // An extra round of requests gives the fetches cancelled above time to reach the keys endpoints
            hello(client, googleAccessToken);
            hello(client, appleAccessToken);
            hello(client, cognitoAccessToken);
            int cachedAppleInvocations = appleInvocations.get();
            int cachedCognitoInvocations = cognitoInvocations.get();
            hello(client, googleAccessToken);
            hello(client, appleAccessToken);
            hello(client, cognitoAccessToken);

            //then:
            assertEquals(1, googleInvocations.get());
            assertEquals(cachedAppleInvocations, appleInvocations.get());
            assertEquals(cachedCognitoInvocations, cognitoInvocations.get());

            // when: ' when you invoke it with a random key, key are cached
            HttpRequest<?> randomSignedJwtRequest = HttpRequest.GET("/hello").bearerAuth(randomSignedJwt());
            HttpClientResponseException e = assertThrows(HttpClientResponseException.class, () -> client.retrieve(randomSignedJwtRequest));

            //then:
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
            assertEquals(1, googleInvocations.get());
            assertEquals(cachedAppleInvocations, appleInvocations.get());
            assertEquals(cachedCognitoInvocations, cognitoInvocations.get());

            //when: 'keys expire, they are fetched again'
            sleep(6_000); // longer than the cache expire-after-write
            hello(client, appleAccessToken);

            //then: 'the JWKS which verifies the token is fetched once'
            assertEquals(cachedAppleInvocations + 1, appleInvocations.get());

            //when:
            hello(client, googleAccessToken);
            hello(client, cognitoAccessToken);

            //then:
            assertTrue(googleInvocations.get() > 1);
            assertTrue(cognitoInvocations.get() > cachedCognitoInvocations);
        }
    }

    private void assertKeyId(JWT jwt, String keyId) {
        assertInstanceOf(SignedJWT.class, jwt);
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
        final AtomicInteger invocations = new AtomicInteger();
        GoogleKeysController(Collection<JwkProvider> jwkProviders, JsonMapper jsonMapper) {
            super(jwkProviders, jsonMapper);
        }

        @Override
        @Get
        @SingleResult
        public Publisher<String> keys() {
            Publisher<String> result = super.keys();
            invocations.incrementAndGet();
            return result;
        }
    }

    @Requires(property = "spec.name", value = "AppleJwksCacheSpec")
    @Controller("/keys")
    @Replaces(KeysController.class)
    static class AppleKeysController extends KeysController {
        final AtomicInteger invocations = new AtomicInteger();
        AppleKeysController(Collection<JwkProvider> jwkProviders, JsonMapper jsonMapper) {
            super(jwkProviders, jsonMapper);
        }

        @Override
        @Get
        @SingleResult
        public Publisher<String> keys() {
            Publisher<String> result = super.keys();
            invocations.incrementAndGet();
            return result;
        }
    }

    @Requires(property = "spec.name", value = "CognitoJwksCacheSpec")
    @Controller("/keys")
    @Replaces(KeysController.class)
    static class CognitoKeysController extends KeysController {
        final AtomicInteger invocations = new AtomicInteger();

        CognitoKeysController(Collection<JwkProvider> jwkProviders, JsonMapper jsonMapper) {
            super(jwkProviders, jsonMapper);
        }

        @Override
        @Get
        @SingleResult
        public Publisher<String> keys() {
            Publisher<String> result = super.keys();
            invocations.incrementAndGet();
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
        private static final String KID = "apple";
        private RSAKey rsaKey;
        private static final JWSAlgorithm ALG = JWSAlgorithm.RS256;
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
        private static final JWSAlgorithm ALG = JWSAlgorithm.RS256;
        private List<JWK> jwks;
        private RSAKey rsaKey;
        String kid = "cognito";

        CognitoSignatureConfiguration() {
            this.rsaKey = null;
            this.jwks = null;
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
        private static final JWSAlgorithm ALG = JWSAlgorithm.RS256;
        private List<JWK> jwks;
        private RSAKey rsaKey;
        String kid = "google";

        GoogleSignatureConfiguration() {
            this.rsaKey = null;
            this.jwks = null;
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
        assertEquals(HttpStatus.OK, response.status());
    }
}

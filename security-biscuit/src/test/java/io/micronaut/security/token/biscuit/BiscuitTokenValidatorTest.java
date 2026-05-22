/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.token.biscuit;

import biscuit.format.schema.Schema;
import com.google.protobuf.ByteString;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.TokenAuthenticationFetcher;
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator;
import jakarta.inject.Singleton;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Authorizer;
import org.biscuitsec.biscuit.token.Biscuit;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BiscuitTokenValidatorTest {

    private static final KeyPair ROOT_KEY = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519);
    private static final KeyPair WRONG_ROOT_KEY = KeyPair.generate(Schema.PublicKey.Algorithm.Ed25519);
    private static final BigInteger ED25519_GROUP_ORDER = new BigInteger(
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
        16
    );

    @Test
    void validatorCanBeDisabled() {
        try (ApplicationContext context = ApplicationContext.run(properties(
            "micronaut.security.token.biscuit.validator-enabled", false
        ))) {
            assertFalse(context.containsBean(BiscuitTokenValidator.class));
        }
    }

    @Test
    void missingRootKeyOrPolicyDoesNotAuthenticate() throws Exception {
        String token = token();
        try (ApplicationContext missingRoot = ApplicationContext.run(properties(
            "micronaut.security.token.biscuit.root-public-key", null
        ));
             ApplicationContext missingPolicy = ApplicationContext.run(properties(
                 "micronaut.security.token.biscuit.policies", List.of()
             ))) {
            BiscuitTokenValidator missingRootValidator = missingRoot.getBean(BiscuitTokenValidator.class);
            BiscuitTokenValidator missingPolicyValidator = missingPolicy.getBean(BiscuitTokenValidator.class);

            assertNull(Mono.from(missingRootValidator.validateToken(token, HttpRequest.GET("/secure"))).block());
            assertNull(Mono.from(missingPolicyValidator.validateToken(token, HttpRequest.GET("/secure"))).block());
        }
    }

    @Test
    void successfulAuthorizationEmitsAuthentication() throws Exception {
        try (ApplicationContext context = ApplicationContext.run(properties())) {
            BiscuitTokenValidator validator = context.getBean(BiscuitTokenValidator.class);

            Authentication result = Mono.from(validator.validateToken(token(), HttpRequest.GET("/secure"))).block();

            assertNotNull(result);
            assertEquals("sherlock", result.getName());
            assertTrue(result.getRoles().contains("ROLE_DETECTIVE"));
            assertFalse(((List<?>) result.getAttributes().get("biscuit.revocationIdentifiers")).isEmpty());
        }
    }

    @Test
    void authorizationFailureReturnsEmptyPublisher() throws Exception {
        try (ApplicationContext context = ApplicationContext.run(properties())) {
            BiscuitTokenValidator validator = context.getBean(BiscuitTokenValidator.class);

            Authentication rejected = Mono.from(validator.validateToken(token(), HttpRequest.POST("/secure", ""))).block();
            Authentication denied = Mono.from(validator.validateToken(deniedToken(), HttpRequest.GET("/secure"))).block();

            assertNull(rejected);
            assertNull(denied);
        }
    }

    @Test
    void malformedWrongKeyRevokedAndRunLimitFailuresReturnEmptyPublisher() throws Exception {
        Biscuit biscuit = biscuit();
        String token = biscuit.serialize_b64url();
        String revocationId = biscuit.revocation_identifiers().get(0).toHex();
        try (ApplicationContext context = ApplicationContext.run(properties());
             ApplicationContext wrongKeyContext = ApplicationContext.run(properties(
                 "micronaut.security.token.biscuit.root-public-key", WRONG_ROOT_KEY.public_key().toHex()
             ));
             ApplicationContext revokedContext = ApplicationContext.run(properties(
                 "micronaut.security.token.biscuit.revoked-identifiers", List.of(revocationId)
             ));
             ApplicationContext runLimitContext = ApplicationContext.run(properties(
                 "micronaut.security.token.biscuit.rules", List.of("generated($name) <- principal($name)"),
                 "micronaut.security.token.biscuit.policies", List.of("allow if generated(\"sherlock\")"),
                 "micronaut.security.token.biscuit.run-limits.max-facts", 1
             ))) {
            assertNull(Mono.from(context.getBean(BiscuitTokenValidator.class).validateToken("not-a-biscuit", HttpRequest.GET("/secure"))).block());
            assertNull(Mono.from(wrongKeyContext.getBean(BiscuitTokenValidator.class).validateToken(token, HttpRequest.GET("/secure"))).block());
            assertNull(Mono.from(revokedContext.getBean(BiscuitTokenValidator.class).validateToken(token, HttpRequest.GET("/secure"))).block());
            assertNull(Mono.from(runLimitContext.getBean(BiscuitTokenValidator.class).validateToken(token, HttpRequest.GET("/secure"))).block());
        }
    }

    @Test
    void nonCanonicalSignatureAcceptedByBiscuitJavaIsRejectedBeforeValidation() throws Exception {
        Biscuit biscuit = biscuit();
        String token = biscuit.serialize_b64url();
        String malleatedToken = malleateAuthoritySignature(token);

        Biscuit malleatedBiscuit = Biscuit.from_b64url(malleatedToken, ROOT_KEY.public_key());
        try (ApplicationContext context = ApplicationContext.run(properties())) {
            Authentication result = Mono.from(context.getBean(BiscuitTokenValidator.class)
                .validateToken(malleatedToken, HttpRequest.GET("/secure"))).block();

            assertNull(result);
            assertNotEquals(
                biscuit.revocation_identifiers().get(0).toHex(),
                malleatedBiscuit.revocation_identifiers().get(0).toHex()
            );
        }
    }

    @Test
    void revocationCheckerFailureReturnsEmptyPublisher() throws Exception {
        try (ApplicationContext context = ApplicationContext.run(properties(
            "spec.name", "BiscuitRevocationCheckerFailure"
        ))) {
            Authentication result = Mono.from(context.getBean(BiscuitTokenValidator.class)
                .validateToken(token(), HttpRequest.GET("/secure"))).block();

            assertNull(result);
        }
    }

    @Test
    void customAuthorizerCustomizerCanAddPolicy() throws Exception {
        try (ApplicationContext context = ApplicationContext.run(properties(
            "spec.name", "BiscuitCustomizer",
            "micronaut.security.token.biscuit.policies", List.of()
        ))) {
            BiscuitTokenValidator validator = context.getBean(BiscuitTokenValidator.class);

            Authentication result = Mono.from(validator.validateToken(tokenForPath("/custom"), HttpRequest.GET("/custom"))).block();

            assertNotNull(result);
            assertEquals("sherlock", result.getName());
        }
    }

    @Test
    void customAuthenticationFactoryCanMapAuthorizedToken() throws Exception {
        try (ApplicationContext context = ApplicationContext.run(properties(
            "spec.name", "BiscuitAuthenticationFactory"
        ))) {
            BiscuitTokenValidator validator = context.getBean(BiscuitTokenValidator.class);

            Authentication result = Mono.from(validator.validateToken(token(), HttpRequest.GET("/secure"))).block();

            assertNotNull(result);
            assertEquals("watson", result.getName());
            assertTrue(result.getRoles().contains("ROLE_ASSISTANT"));
        }
    }

    @Test
    void bearerTokenAuthenticationFetcherCanUseBiscuitValidator() throws Exception {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, properties())) {
            TokenAuthenticationFetcher fetcher = server.getApplicationContext().getBean(TokenAuthenticationFetcher.class);

            Authentication result = Mono.from(fetcher.fetchAuthentication(HttpRequest.GET("/secure").bearerAuth(token()))).block();

            assertNotNull(result);
            assertEquals("sherlock", result.getName());
        }
    }

    @Test
    void protectedRouteAcceptsValidBiscuitBearerTokenAndRejectsFailedCaveat() throws Exception {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, properties(
            "spec.name", "BiscuitHttp"
        ));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            String accepted = client.retrieve(HttpRequest.GET("/secure")
                .accept(MediaType.TEXT_PLAIN)
                .bearerAuth(token()));
            HttpClientResponseException rejected = assertThrows(
                HttpClientResponseException.class,
                () -> client.retrieve(HttpRequest.GET("/secure")
                    .accept(MediaType.TEXT_PLAIN)
                    .bearerAuth(tokenForPath("/other")))
            );

            assertEquals("sherlock", accepted);
            assertEquals(HttpStatus.UNAUTHORIZED, rejected.getStatus());
        }
    }

    @Test
    void jwtBearerAuthenticationStillWorksWhenBiscuitValidatorIsPresent() throws Exception {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, properties(
            "spec.name", "BiscuitHttp",
            "micronaut.security.token.jwt.signatures.secret.generator.secret", "pleaseChangeThisSecretForANewOne"
        ));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            JwtTokenGenerator tokenGenerator = server.getApplicationContext().getBean(JwtTokenGenerator.class);
            String jwt = tokenGenerator.generateToken(Map.of(
                "sub", "jwt-user",
                "roles", List.of("ROLE_JWT")
            )).orElseThrow();
            BlockingHttpClient client = httpClient.toBlocking();

            String accepted = client.retrieve(HttpRequest.GET("/jwt")
                .accept(MediaType.TEXT_PLAIN)
                .bearerAuth(jwt));

            assertEquals("jwt-user", accepted);
        }
    }

    private static Map<String, Object> properties(Object... overrides) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("micronaut.security.authentication", "bearer");
        properties.put("micronaut.security.token.biscuit.root-public-key", ROOT_KEY.public_key().toHex());
        properties.put("micronaut.security.token.biscuit.policies", List.of("allow if resource(\"/secure\"), operation(\"GET\")"));
        for (int i = 0; i < overrides.length; i += 2) {
            if (overrides[i + 1] == null) {
                properties.remove(overrides[i].toString());
            } else {
                properties.put(overrides[i].toString(), overrides[i + 1]);
            }
        }
        return properties;
    }

    private static String token() throws Exception {
        return tokenForPath("/secure");
    }

    private static String tokenForPath(String path) throws Exception {
        return biscuitForPath(path).serialize_b64url();
    }

    private static Biscuit biscuit() throws Exception {
        return biscuitForPath("/secure");
    }

    private static Biscuit biscuitForPath(String path) throws Exception {
        return Biscuit.builder(ROOT_KEY)
            .add_authority_fact("principal(\"sherlock\")")
            .add_authority_fact("role(\"ROLE_DETECTIVE\")")
            .add_authority_check("check if resource(\"" + path + "\")")
            .build();
    }

    private static String deniedToken() throws Exception {
        return Biscuit.builder(ROOT_KEY)
            .add_authority_fact("principal(\"moriarty\")")
            .add_authority_check("check if resource(\"/denied\")")
            .build()
            .serialize_b64url();
    }

    private static String malleateAuthoritySignature(String token) throws Exception {
        Schema.Biscuit biscuit = Schema.Biscuit.parseFrom(Base64.getUrlDecoder().decode(padBase64Url(token)));
        Schema.SignedBlock authority = biscuit.getAuthority()
            .toBuilder()
            .setSignature(ByteString.copyFrom(malleateSignature(biscuit.getAuthority().getSignature().toByteArray())))
            .build();
        return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(biscuit.toBuilder().setAuthority(authority).build().toByteArray());
    }

    private static byte[] malleateSignature(byte[] signature) {
        byte[] malleated = signature.clone();
        byte[] scalar = new byte[32];
        for (int i = 0; i < scalar.length; i++) {
            scalar[scalar.length - 1 - i] = signature[32 + i];
        }
        byte[] malleatedScalar = ED25519_GROUP_ORDER.add(new BigInteger(1, scalar)).toByteArray();
        for (int i = 0; i < scalar.length; i++) {
            int source = malleatedScalar.length - 1 - i;
            malleated[32 + i] = source >= 0 ? malleatedScalar[source] : 0;
        }
        return malleated;
    }

    private static String padBase64Url(String token) {
        int remainder = token.length() % 4;
        return switch (remainder) {
            case 0 -> token;
            case 2 -> token + "==";
            case 3 -> token + "=";
            default -> token;
        };
    }

    @Requires(property = "spec.name", value = "BiscuitCustomizer")
    @Singleton
    static class RequestPathPolicyCustomizer implements BiscuitAuthorizerCustomizer {

        @Override
        public void customize(Authorizer authorizer, Biscuit biscuit, HttpRequest<?> request) throws Error {
            if (request != null && "/custom".equals(request.getPath())) {
                authorizer.add_policy("allow if resource(\"/custom\")");
            }
        }
    }

    @Requires(property = "spec.name", value = "BiscuitAuthenticationFactory")
    @Singleton
    static class CustomBiscuitAuthenticationFactory implements BiscuitAuthenticationFactory {

        @Override
        public Optional<Authentication> createAuthentication(BiscuitAuthenticationContext context) {
            return Optional.of(Authentication.build("watson", List.of("ROLE_ASSISTANT")));
        }
    }

    @Requires(property = "spec.name", value = "BiscuitRevocationCheckerFailure")
    @Singleton
    static class FailingBiscuitRevocationChecker implements BiscuitRevocationChecker {

        @Override
        public boolean isRevoked(Biscuit biscuit, List<String> revocationIdentifiers, HttpRequest<?> request) {
            throw new IllegalStateException("Revocation store unavailable");
        }
    }

    @Requires(property = "spec.name", value = "BiscuitHttp")
    @Controller
    static class ProtectedController {

        @Produces(MediaType.TEXT_PLAIN)
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get("/secure")
        String secure(Authentication authentication) {
            return authentication.getName();
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Secured("ROLE_JWT")
        @Get("/jwt")
        String jwt(Authentication authentication) {
            return authentication.getName();
        }
    }
}

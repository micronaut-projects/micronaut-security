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
package io.micronaut.security.token.macaroons;

import com.github.nitram509.jmacaroons.Macaroon;
import com.github.nitram509.jmacaroons.MacaroonsSerializer;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.TokenAuthenticationFetcher;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MacaroonTokenValidatorTest {

    private static final String SECRET = "change-this-root-secret-for-production-tests";

    @Test
    void generatorAndValidatorAreAbsentWithoutSecret() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            "micronaut.security.authentication", "bearer"
        ))) {
            assertFalse(context.containsBean(MacaroonTokenGenerator.class));
            assertFalse(context.containsBean(MacaroonTokenValidator.class));
        }
    }

    @Test
    void generatorAndValidatorAreAbsentWhenMacaroonsAreDisabled() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            "micronaut.security.authentication", "bearer",
            "micronaut.security.token.macaroons.secret", SECRET,
            "micronaut.security.token.macaroons.enabled", false
        ))) {
            assertFalse(context.containsBean(MacaroonTokenGenerator.class));
            assertFalse(context.containsBean(MacaroonTokenValidator.class));
        }
    }

    @Test
    void generatedTokenCanBeValidated() {
        try (ApplicationContext context = ApplicationContext.run(properties())) {
            MacaroonTokenGenerator generator = context.getBean(MacaroonTokenGenerator.class);
            MacaroonTokenValidator validator = context.getBean(MacaroonTokenValidator.class);

            Authentication authentication = Authentication.build(
                "sherlock",
                List.of("ROLE_DETECTIVE", "ROLE_ADMIN"),
                Map.of("department", "baker-street")
            );
            String token = generator.generateToken(authentication, 60).orElseThrow();

            Authentication result = Mono.from(validator.validateToken(token, HttpRequest.GET("/secure"))).block();

            assertNotNull(result);
            assertEquals("sherlock", result.getName());
            assertTrue(result.getRoles().contains("ROLE_DETECTIVE"));
            assertEquals("baker-street", result.getAttributes().get("department"));
        }
    }

    @Test
    void invalidTokensReturnEmptyPublisher() {
        try (ApplicationContext context = ApplicationContext.run(properties());
             ApplicationContext wrongSecretContext = ApplicationContext.run(properties("micronaut.security.token.macaroons.secret", "wrong-secret"))) {
            MacaroonTokenGenerator generator = context.getBean(MacaroonTokenGenerator.class);
            MacaroonTokenValidator validator = context.getBean(MacaroonTokenValidator.class);
            MacaroonTokenValidator wrongSecretValidator = wrongSecretContext.getBean(MacaroonTokenValidator.class);
            String token = generator.generateToken(Authentication.build("sherlock"), 60).orElseThrow();
            String expired = generator.generateToken(Authentication.build("watson"), -1).orElseThrow();

            assertNull(Mono.from(validator.validateToken("not-a-macaroon", HttpRequest.GET("/secure"))).block());
            assertNull(Mono.from(validator.validateToken(tamper(token), HttpRequest.GET("/secure"))).block());
            assertNull(Mono.from(wrongSecretValidator.validateToken(token, HttpRequest.GET("/secure"))).block());
            assertNull(Mono.from(validator.validateToken(expired, HttpRequest.GET("/secure"))).block());
            assertNull(Mono.from(validator.validateToken(addCaveat(token, "unknown = true"), HttpRequest.GET("/secure"))).block());
            assertNull(Mono.from(validator.validateToken(addThirdPartyCaveat(token), HttpRequest.GET("/secure"))).block());
        }
    }

    @Test
    void caveatVerifierExceptionsReturnEmptyPublisherForInvalidToken() {
        ThrowingCaveatVerifier.invocations.set(0);
        try (ApplicationContext context = ApplicationContext.run(properties("spec.name", ThrowingCaveatVerifier.class.getSimpleName()));
             ApplicationContext wrongSecretContext = ApplicationContext.run(properties("micronaut.security.token.macaroons.secret", "wrong-secret"))) {
            MacaroonTokenGenerator wrongSecretGenerator = wrongSecretContext.getBean(MacaroonTokenGenerator.class);
            MacaroonTokenValidator validator = context.getBean(MacaroonTokenValidator.class);
            String token = wrongSecretGenerator.generateToken(Authentication.build("sherlock"), 60).orElseThrow();
            String caveated = addCaveat(token, "throws = malformed");

            Authentication result = assertDoesNotThrow(() -> Mono.from(validator.validateToken(caveated, HttpRequest.GET("/secure"))).block());

            assertNull(result);
            assertEquals(1, ThrowingCaveatVerifier.invocations.get());
        }
    }

    @Test
    void expirationClaimWithUnsupportedTypeIsRejected() {
        try (ApplicationContext context = ApplicationContext.run(properties())) {
            MacaroonTokenGenerator generator = context.getBean(MacaroonTokenGenerator.class);
            MacaroonTokenValidator validator = context.getBean(MacaroonTokenValidator.class);
            String token = generator.generateToken(Map.of(
                Claims.SUBJECT, "sherlock",
                Claims.EXPIRATION_TIME, "1"
            )).orElseThrow();

            Authentication result = Mono.from(validator.validateToken(token, HttpRequest.GET("/secure"))).block();

            assertNull(result);
        }
    }

    @Test
    void notBeforeClaimWithUnsupportedTypeIsRejected() {
        try (ApplicationContext context = ApplicationContext.run(properties())) {
            MacaroonTokenGenerator generator = context.getBean(MacaroonTokenGenerator.class);
            MacaroonTokenValidator validator = context.getBean(MacaroonTokenValidator.class);
            String token = generator.generateToken(Map.of(
                Claims.SUBJECT, "sherlock",
                Claims.NOT_BEFORE, Long.MAX_VALUE
            )).orElseThrow();

            Authentication result = Mono.from(validator.validateToken(token, HttpRequest.GET("/secure"))).block();

            assertNull(result);
        }
    }

    @Test
    void customRequestAwareCaveatVerifierCanSatisfyCaveat() {
        try (ApplicationContext context = ApplicationContext.run(properties("spec.name", MacaroonTokenValidatorTest.class.getSimpleName()))) {
            MacaroonTokenGenerator generator = context.getBean(MacaroonTokenGenerator.class);
            MacaroonTokenValidator validator = context.getBean(MacaroonTokenValidator.class);
            String token = generator.generateToken(Authentication.build("sherlock"), 60).orElseThrow();
            String caveated = addCaveat(token, "request-path = /secure");

            Authentication result = Mono.from(validator.validateToken(caveated, HttpRequest.GET("/secure"))).block();
            Authentication rejected = Mono.from(validator.validateToken(caveated, HttpRequest.GET("/other"))).block();

            assertNotNull(result);
            assertEquals("sherlock", result.getName());
            assertNull(rejected);
        }
    }

    @Test
    void bearerTokenAuthenticationFetcherCanUseMacaroonValidator() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, properties())) {
            ApplicationContext context = server.getApplicationContext();
            MacaroonTokenGenerator generator = context.getBean(MacaroonTokenGenerator.class);
            TokenAuthenticationFetcher fetcher = context.getBean(TokenAuthenticationFetcher.class);
            String token = generator.generateToken(Authentication.build("sherlock"), 60).orElseThrow();

            Authentication result = Mono.from(fetcher.fetchAuthentication(HttpRequest.GET("/secure").bearerAuth(token))).block();

            assertNotNull(result);
            assertEquals("sherlock", result.getName());
        }
    }

    private static Map<String, Object> properties(Object... overrides) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("micronaut.security.authentication", "bearer");
        properties.put("micronaut.security.token.macaroons.secret", SECRET);
        properties.put("micronaut.security.token.macaroons.serialization", MacaroonSerialization.V2);
        for (int i = 0; i < overrides.length; i += 2) {
            properties.put(overrides[i].toString(), overrides[i + 1]);
        }
        return properties;
    }

    private static String addCaveat(String token, String caveat) {
        Macaroon macaroon = Macaroon.deserialize(token, MacaroonsSerializer.V2);
        return Macaroon.builder(macaroon).addCaveat(caveat).build().serialize(MacaroonsSerializer.V2);
    }

    private static String addThirdPartyCaveat(String token) {
        Macaroon macaroon = Macaroon.deserialize(token, MacaroonsSerializer.V2);
        return Macaroon.builder(macaroon)
            .addCaveat("https://auth.example", "third-party-secret", "third-party-identifier")
            .build()
            .serialize(MacaroonsSerializer.V2);
    }

    private static String tamper(String token) {
        char replacement = token.charAt(token.length() - 1) == 'a' ? 'b' : 'a';
        return token.substring(0, token.length() - 1) + replacement;
    }

    @Requires(property = "spec.name", value = "MacaroonTokenValidatorTest")
    @Singleton
    static class RequestPathCaveatVerifier implements MacaroonCaveatVerifier {

        @Override
        public boolean verify(MacaroonCaveat caveat, HttpRequest<?> request) {
            return request != null && caveat.getValue().equals("request-path = " + request.getPath());
        }
    }

    @Requires(property = "spec.name", value = "ThrowingCaveatVerifier")
    @Singleton
    static class ThrowingCaveatVerifier implements MacaroonCaveatVerifier {

        static final AtomicInteger invocations = new AtomicInteger();

        @Override
        public boolean verify(MacaroonCaveat caveat, HttpRequest<?> request) {
            invocations.incrementAndGet();
            if (caveat.getValue().equals("throws = malformed")) {
                throw new IllegalArgumentException("malformed caveat");
            }
            return false;
        }
    }
}

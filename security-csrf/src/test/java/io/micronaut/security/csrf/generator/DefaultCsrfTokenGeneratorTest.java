/*
 * Copyright 2026 original authors
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
package io.micronaut.security.csrf.generator;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.filters.SecurityFilter;
import org.junit.jupiter.api.Test;

import io.micronaut.http.cookie.SameSite;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.session.SessionIdResolver;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.temporal.TemporalAmount;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The HMAC of a signed CSRF token is bound to the user authenticated in the request.
 */
class DefaultCsrfTokenGeneratorTest {

    @Test
    void hmacIsBoundToTheAuthenticatedUser() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            "micronaut.security.csrf.signature-key", "test-fixture-not-a-secret-csrf-signature-key"))) {
            CsrfHmacTokenGenerator<HttpRequest<?>> generator = context.getBean(CsrfHmacTokenGenerator.class);
            CsrfTokenValidator<HttpRequest<?>> validator = context.getBean(CsrfTokenValidator.class);
            String randomValue = "abcdefg";

            String anonymousHmac = generator.hmac(anonymousRequest(), randomValue);
            String sherlockHmac = generator.hmac(authenticatedRequest("sherlock"), randomValue);
            String moriartyHmac = generator.hmac(authenticatedRequest("moriarty"), randomValue);
            assertNotEquals(anonymousHmac, sherlockHmac);
            assertNotEquals(sherlockHmac, moriartyHmac);

            // the HMAC calculated for an explicit authentication matches the one resolved from the request
            assertEquals(sherlockHmac, generator.hmac(anonymousRequest(), Authentication.build("sherlock"), randomValue));
            assertEquals(anonymousHmac, generator.hmac(anonymousRequest(), null, randomValue));

            // a token generated for a user is only valid for a request authenticated as that user
            String sherlockToken = generator.generateCsrfToken(anonymousRequest(), Authentication.build("sherlock"));
            assertTrue(validator.validateCsrfToken(authenticatedRequest("sherlock", sherlockToken), sherlockToken));
            assertFalse(validator.validateCsrfToken(authenticatedRequest("moriarty", sherlockToken), sherlockToken));
            assertFalse(validator.validateCsrfToken(anonymousRequest(sherlockToken), sherlockToken));

            // a token generated for an anonymous request is not valid once the request is authenticated
            String anonymousToken = generator.generateCsrfToken(anonymousRequest());
            assertTrue(validator.validateCsrfToken(anonymousRequest(anonymousToken), anonymousToken));
            assertFalse(validator.validateCsrfToken(authenticatedRequest("sherlock", anonymousToken), anonymousToken));
        }
    }

    @Test
    void hmacMessagePayloadSeparatesSessionIdUserAndRandomValue() {
        assertEquals("0!!0!!7!abcdefg", DefaultCsrfTokenGenerator.hmacMessagePayload("", "", "abcdefg"));
        assertEquals("12!MTIzNDU2Nzg5!12!c2hlcmxvY2s=!7!abcdefg", DefaultCsrfTokenGenerator.hmacMessagePayload("123456789", "sherlock", "abcdefg"));
        assertNotEquals(DefaultCsrfTokenGenerator.hmacMessagePayload("123456789", "", "abcdefg"),
            DefaultCsrfTokenGenerator.hmacMessagePayload("", "123456789", "abcdefg"));
    }

    private static final String SECRET = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
    private static final String NON_ASCII_SESSION_ID = "sesi\u00f3n-\u00f1-\u65e5\u672c";
    private static final String RANDOM_VALUE = "cmFuZG9tLXZhbHVl";

    @Test
    void hmacMessagePayloadEncodesSessionIdAndUserAsUtf8() {
        String base64SessionId = Base64.getEncoder().encodeToString(NON_ASCII_SESSION_ID.getBytes(StandardCharsets.UTF_8));
        String expected = base64SessionId.length() + "!" + base64SessionId + "!0!!" + RANDOM_VALUE.length() + "!" + RANDOM_VALUE;

        assertEquals(expected, DefaultCsrfTokenGenerator.hmacMessagePayload(NON_ASCII_SESSION_ID, "", RANDOM_VALUE));
    }

    @Test
    void hmacWithNonAsciiSessionIdIsCharsetIndependent() throws NoSuchAlgorithmException, InvalidKeyException {
        SessionIdResolver<Object> sessionIdResolver = request -> Optional.of(NON_ASCII_SESSION_ID);
        DefaultCsrfTokenGenerator<Object> generator = new DefaultCsrfTokenGenerator<>(new TestCsrfConfiguration(SECRET), sessionIdResolver);

        String base64SessionId = Base64.getEncoder().encodeToString(NON_ASCII_SESSION_ID.getBytes(StandardCharsets.UTF_8));
        String message = base64SessionId.length() + "!" + base64SessionId + "!0!!" + RANDOM_VALUE.length() + "!" + RANDOM_VALUE;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String expected = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));

        // Values precomputed with an explicit UTF-8 Mac; they must not change with the JVM's file.encoding
        assertEquals("24!c2VzacOzbi3DsS3ml6XmnKw=!0!!16!cmFuZG9tLXZhbHVl", message);
        assertEquals("N09VNQUrf7ApsEtc04iHvg7Jzv8bV2gpM5gGB2Fjr4I", expected);
        assertEquals(expected, generator.hmac(new Object(), null, RANDOM_VALUE));
    }

    @Test
    void hmacDoesNotCollapseProviderQualifiedPrincipalsSharingTheSameRawSubject() {
        // e.g. authentications validated via the UserInfo endpoint of two OpenID providers: the name is qualified
        // with the provider but the raw sub attribute is retained, and there is no session id for a bearer token.
        SessionIdResolver<Object> noSession = request -> Optional.empty();
        DefaultCsrfTokenGenerator<Object> generator = new DefaultCsrfTokenGenerator<>(new TestCsrfConfiguration(SECRET), noSession);
        Authentication providerA = Authentication.build("provider-a:victim", Map.of("sub", "victim", "oauth2Provider", "provider-a"));
        Authentication providerB = Authentication.build("provider-b:victim", Map.of("sub", "victim", "oauth2Provider", "provider-b"));

        assertNotEquals(generator.hmac(new Object(), providerA, RANDOM_VALUE), generator.hmac(new Object(), providerB, RANDOM_VALUE));

        // the binding is the principal name, which is the sub claim of a token issued at login for the same authentication
        Authentication rebuiltFromToken = Authentication.build("provider-a:victim", Map.of("sub", "provider-a:victim", "oauth2Provider", "provider-a"));
        assertEquals(generator.hmac(new Object(), providerA, RANDOM_VALUE), generator.hmac(new Object(), rebuiltFromToken, RANDOM_VALUE));
        assertEquals(generator.hmac(new Object(), Authentication.build("provider-a:victim"), RANDOM_VALUE), generator.hmac(new Object(), providerA, RANDOM_VALUE));
    }

    @Test
    void hmacBindsThePrincipalNameOnlyAndToleratesNullNames() {
        SessionIdResolver<Object> sessionIdResolver = request -> Optional.of("sid");
        DefaultCsrfTokenGenerator<Object> generator = new DefaultCsrfTokenGenerator<>(new TestCsrfConfiguration(SECRET), sessionIdResolver);

        // attributes do not take part in the binding: login handlers issuing a token supply the authentication named as
        // token based authentication names the user on later requests
        Authentication withAttributes = Authentication.build("sherlock", Map.of("sub", "idp-subject", "email", "sherlock@example.com"));
        assertEquals(generator.hmac(new Object(), Authentication.build("sherlock"), RANDOM_VALUE), generator.hmac(new Object(), withAttributes, RANDOM_VALUE));

        // a different user is rejected even if the attributes are the same
        Authentication other = Authentication.build("moriarty", Map.of("sub", "idp-subject", "email", "sherlock@example.com"));
        assertNotEquals(generator.hmac(new Object(), withAttributes, RANDOM_VALUE), generator.hmac(new Object(), other, RANDOM_VALUE));

        // an authentication without a name does not fail
        Authentication nameless = new Authentication() {
            @Override
            public Map<String, Object> getAttributes() {
                return Map.of();
            }

            @Override
            public String getName() {
                return null;
            }
        };
        assertEquals(generator.hmac(new Object(), null, RANDOM_VALUE), generator.hmac(new Object(), nameless, RANDOM_VALUE));
    }

    private static MutableHttpRequest<?> anonymousRequest() {
        return new SimpleHttpRequest<>(HttpMethod.POST, "/password/change", null);
    }

    private static MutableHttpRequest<?> anonymousRequest(String csrfToken) {
        return anonymousRequest().cookie(Cookie.of("__Host-csrfToken", csrfToken));
    }

    private static HttpRequest<?> authenticatedRequest(String username) {
        return anonymousRequest().setAttribute(SecurityFilter.AUTHENTICATION, Authentication.build(username));
    }

    private static HttpRequest<?> authenticatedRequest(String username, String csrfToken) {
        return anonymousRequest(csrfToken).setAttribute(SecurityFilter.AUTHENTICATION, Authentication.build(username));
    }

    private static final class TestCsrfConfiguration implements CsrfConfiguration {
        private final String secretKey;

        TestCsrfConfiguration(String secretKey) {
            this.secretKey = secretKey;
        }

        @Override
        public int getRandomValueSize() {
            return 16;
        }

        @Override
        public String getSecretKey() {
            return secretKey;
        }

        @Override
        public String getHeaderName() {
            return "X-CSRF-TOKEN";
        }

        @Override
        public String getHttpSessionName() {
            return "csrfToken";
        }

        @Override
        public String getFieldName() {
            return "csrfToken";
        }

        @Override
        public String getCookieName() {
            return "__Host-csrfToken";
        }

        @Override
        public Optional<String> getCookieDomain() {
            return Optional.empty();
        }

        @Override
        public Optional<String> getCookiePath() {
            return Optional.of("/");
        }

        @Override
        public Optional<Boolean> isCookieHttpOnly() {
            return Optional.of(true);
        }

        @Override
        public Optional<Boolean> isCookieSecure() {
            return Optional.of(true);
        }

        @Override
        public Optional<TemporalAmount> getCookieMaxAge() {
            return Optional.empty();
        }

        @Override
        public Optional<SameSite> getCookieSameSite() {
            return Optional.of(SameSite.Strict);
        }
    }
}

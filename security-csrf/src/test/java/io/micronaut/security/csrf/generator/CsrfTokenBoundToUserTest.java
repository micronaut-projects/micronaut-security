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

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.security.token.cookie.TokenCookieConfigurationProperties;
import io.micronaut.security.utils.HMacUtils;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With {@code micronaut.security.authentication=cookie} and a CSRF signature key, the signed CSRF token issued at
 * login must be bound to the authenticated user. A correctly signed token issued to one account must not pass the
 * CSRF validation of a request authenticated as another account, even if an attacker manages to plant the token
 * in the victim's CSRF cookie.
 */
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "test-fixture-not-a-secret-jwt-signature-key")
@Property(name = "micronaut.security.csrf.signature-key", value = "test-fixture-not-a-secret-csrf-signature-key")
@Property(name = "micronaut.security.redirect.enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csrf.filter.regex-pattern", value = "^(?!\\/login).*$")
@Property(name = "spec.name", value = "CsrfTokenBoundToUserTest")
@MicronautTest
class CsrfTokenBoundToUserTest {
    private static final String CSRF_COOKIE_NAME = "__Host-csrfToken";

    @Test
    void csrfTokenIssuedToOneUserIsRejectedForAnotherUser(@Client("/") HttpClient httpClient,
                                                          CsrfConfiguration csrfConfiguration,
                                                          CsrfTokenGenerator<HttpRequest<?>> csrfTokenGenerator) throws NoSuchAlgorithmException, InvalidKeyException {
        BlockingHttpClient client = httpClient.toBlocking();

        LoginCookies attacker = login(client, "moriarty");
        LoginCookies victim = login(client, "sherlock");
        assertNotEquals(attacker.csrfToken(), victim.csrfToken());

        // accepted: each user submits the CSRF token issued at their own login
        assertOk(client, victim.jwt(), victim.csrfToken());
        assertOk(client, attacker.jwt(), attacker.csrfToken());

        // rejected: the attacker's correctly signed token planted in the victim's cookie and submitted with the victim's JWT
        assertDenied(client, victim.jwt(), attacker.csrfToken());

        // rejected: a token signed without binding it to a session or user
        String randomValue = "abcdefg";
        String unboundToken = HMacUtils.base64EncodedHmacSha256(DefaultCsrfTokenGenerator.hmacMessagePayload("", "", randomValue), csrfConfiguration.getSecretKey())
                + CsrfHmacTokenGenerator.HMAC_RANDOM_SEPARATOR + randomValue;
        assertDenied(client, victim.jwt(), unboundToken);

        // rejected: a token generated for an anonymous request is not valid for an authenticated user
        String anonymousToken = csrfTokenGenerator.generateCsrfToken(new SimpleHttpRequest<>(HttpMethod.POST, "/password/change", null));
        assertDenied(client, victim.jwt(), anonymousToken);

        // accepted: a token generated for the victim is valid for the victim ...
        Authentication victimAuthentication = Authentication.build("sherlock");
        String victimToken = csrfTokenGenerator.generateCsrfToken(new SimpleHttpRequest<>(HttpMethod.POST, "/password/change", null), victimAuthentication);
        assertOk(client, victim.jwt(), victimToken);
        // ... but not for the attacker
        assertDenied(client, attacker.jwt(), victimToken);
    }

    private static LoginCookies login(BlockingHttpClient client, String username) {
        HttpRequest<?> loginRequest = HttpRequest.POST("/login", Map.of("username", username, "password", "password"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        HttpResponse<?> loginRsp = assertDoesNotThrow(() -> client.exchange(loginRequest));
        assertEquals(HttpStatus.OK, loginRsp.getStatus());
        Optional<Cookie> jwt = loginRsp.getCookie(TokenCookieConfigurationProperties.DEFAULT_COOKIENAME);
        assertTrue(jwt.isPresent());
        Optional<Cookie> csrf = loginRsp.getCookie(CSRF_COOKIE_NAME);
        assertTrue(csrf.isPresent());
        return new LoginCookies(jwt.get().getValue(), csrf.get().getValue());
    }

    private static void assertDenied(BlockingHttpClient client, String jwt, String csrfToken) {
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(passwordChange(jwt, csrfToken)));
        assertEquals(HttpStatus.FORBIDDEN, ex.getStatus());
    }

    private static void assertOk(BlockingHttpClient client, String jwt, String csrfToken) {
        HttpResponse<String> response = assertDoesNotThrow(() -> client.exchange(passwordChange(jwt, csrfToken), String.class));
        assertEquals(HttpStatus.OK, response.getStatus());
    }

    private static HttpRequest<?> passwordChange(String jwt, String csrfToken) {
        return HttpRequest.POST("/password/change", new PasswordChangeForm("sherlock", "evil", csrfToken))
                .cookie(Cookie.of(TokenCookieConfigurationProperties.DEFAULT_COOKIENAME, jwt))
                .cookie(Cookie.of(CSRF_COOKIE_NAME, csrfToken))
                .accept(MediaType.TEXT_HTML)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    record LoginCookies(String jwt, String csrfToken) {
    }

    @Requires(property = "spec.name", value = "CsrfTokenBoundToUserTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(List.of(new SuccessAuthenticationScenario("sherlock"), new SuccessAuthenticationScenario("moriarty")));
        }
    }

    @Requires(property = "spec.name", value = "CsrfTokenBoundToUserTest")
    @Controller
    static class PasswordChangeController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_HTML)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/password/change")
        String changePassword(@Body PasswordChangeForm passwordChangeForm, Authentication authentication) {
            return authentication.getName();
        }
    }

    @Serdeable
    record PasswordChangeForm(
            String username,
            String password,
            String csrfToken) {
    }
}

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
package io.micronaut.security.rules;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.MockAuthenticationProvider;
import io.micronaut.security.SuccessAuthenticationScenario;
import io.micronaut.security.annotation.Secured;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A {@link Secured} expression that evaluates to null, which happens for anonymous requests when the expression
 * navigates the user with {@code user?.}, must reject the request instead of deferring to later rules.
 */
@Property(name = "spec.name", value = "SecuredAnnotationRuleNullExpressionTest")
@Property(name = "micronaut.security.reject-not-found", value = StringUtils.FALSE)
@Property(name = "micronaut.security.intercept-url-map[0].pattern", value = "/**")
@Property(name = "micronaut.security.intercept-url-map[0].access[0]", value = "isAnonymous()")
@MicronautTest
class SecuredAnnotationRuleNullExpressionTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @ParameterizedTest
    @ValueSource(strings = {"/secured/email", "/secured/role"})
    void anonymousRequestsAreRejectedWhenTheExpressionEvaluatesToNull(String path) {
        BlockingHttpClient client = httpClient.toBlocking();
        assertStatus(client, HttpRequest.GET(path), HttpStatus.UNAUTHORIZED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/secured/email", "/secured/role"})
    void authenticatedUsersNotMatchingTheExpressionAreForbidden(String path) {
        BlockingHttpClient client = httpClient.toBlocking();
        assertStatus(client, HttpRequest.GET(path).basicAuth("moriarty", "password"), HttpStatus.FORBIDDEN);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/secured/email", "/secured/role"})
    void authenticatedUsersMatchingTheExpressionAreAllowed(String path) {
        BlockingHttpClient client = httpClient.toBlocking();
        assertEquals("secret", client.retrieve(HttpRequest.GET(path).accept(MediaType.TEXT_PLAIN).basicAuth("sherlock", "password")));
    }

    @Test
    void interceptUrlMapStillAllowsAnonymousAccessToUnsecuredRoutes() {
        BlockingHttpClient client = httpClient.toBlocking();
        assertEquals("public", client.retrieve(HttpRequest.GET("/secured/public").accept(MediaType.TEXT_PLAIN)));
    }

    private static void assertStatus(BlockingHttpClient client, MutableHttpRequest<?> request, HttpStatus expectedStatus) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(request.accept(MediaType.TEXT_PLAIN)),
            () -> "GET " + request.getUri() + " should have been rejected");
        assertEquals(expectedStatus, exception.getStatus(), () -> "GET " + request.getUri());
    }

    @Requires(property = "spec.name", value = "SecuredAnnotationRuleNullExpressionTest")
    @Controller("/secured")
    @Produces(MediaType.TEXT_PLAIN)
    static class SecuredExpressionController {

        @Secured("#{ user?.attributes?.get('email') == 'sherlock@micronaut.example' }")
        @Get("/email")
        String email() {
            return "secret";
        }

        @Secured("#{ user?.roles?.contains('ROLE_DETECTIVE') }")
        @Get("/role")
        String role() {
            return "secret";
        }

        @Get("/public")
        String publicRoute() {
            return "public";
        }
    }

    @Requires(property = "spec.name", value = "SecuredAnnotationRuleNullExpressionTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(List.of(
                new SuccessAuthenticationScenario("sherlock", List.of("ROLE_DETECTIVE"), Map.of("email", "sherlock@micronaut.example")),
                new SuccessAuthenticationScenario("moriarty", List.of("ROLE_VILLAIN"), Map.of("email", "moriarty@micronaut.example"))
            ));
        }
    }
}

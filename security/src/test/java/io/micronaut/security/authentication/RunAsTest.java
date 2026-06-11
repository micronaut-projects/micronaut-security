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
package io.micronaut.security.docs.authentication;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.ClientAuthentication;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import io.micronaut.security.context.SecurityContextHolder;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.annotation.security.RunAs;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Property(name = "spec.name", value = "RunAsTest")
@MicronautTest
class RunAsTest {

    @Test
    void verifyYouCanUseTheRunAsAnnotationToChangeTheSecurityContextHolderForTheScopeOfAClass(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        List<ClientAuthentication> authentications = client.retrieve(
                HttpRequest.GET("/runAs").basicAuth("john", "ilikedaenerys"),
                Argument.listOf(ClientAuthentication.class)
        );
        Authentication runAsExpected = Authentication.build(
                "aegon",
                List.of("ROLE_KING"),
                Map.of("family_name", "Targaryen", "roles", List.of("ROLE_KING"))
        );
        Authentication authentication = authentications.get(0);
        assertNotNull(authentication);
        assertEquals(runAsExpected.getName(), authentication.getName());
        assertEquals(runAsExpected.getRoles().stream().toList(), authentication.getRoles().stream().toList());
        assertEquals(runAsExpected.getAttributes(), authentication.getAttributes());

        Authentication expected = Authentication.build(
                "john",
                List.of("ROLE_STARK"),
                Map.of("family_name", "Snow", "given_name", "John", "roles", List.of("ROLE_STARK"))
        );
        authentication = authentications.get(1);
        assertNotNull(authentication);
        assertEquals(expected.getName(), authentication.getName());
        assertEquals(expected.getRoles().stream().toList(), authentication.getRoles().stream().toList());
        assertEquals(expected.getAttributes(), authentication.getAttributes());
    }

    @Requires(property = "spec.name", value = "RunAsTest")
    @Singleton
    static class RunAsAuthenticationProvider<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        public @NonNull AuthenticationResponse authenticate(@Nullable HttpRequest<B> requestContext,
                                                            @NonNull AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success(
                    "john",
                    List.of("ROLE_STARK"),
                    Map.of("family_name", "Snow", "given_name", "John")
            );
        }
    }

    @Requires(property = "spec.name", value = "RunAsTest")
    @Controller("/runAs")
    static class RunAsController {
        private final RunAsAuthService runAuthService;
        private final AuthService authService;

        RunAsController(RunAsAuthService runAuthService,
                        AuthService authService) {
            this.runAuthService = runAuthService;
            this.authService = authService;
        }

        @Secured("ROLE_STARK")
        @Get
        List<Authentication> index() {
            return List.of(runAuthService.changeAuth(), authService.auth());
        }
    }

    @Requires(property = "spec.name", value = "RunAsTest")
    @Singleton
    static class AuthService {
        Authentication auth() {
            return SecurityContextHolder.getSecurityContext().getAuthentication();
        }
    }

    @RunAs("""
            {"name":"aegon","attributes":{"family_name":"Targaryen","roles":["ROLE_KING"]}}""")
    @Singleton
    static class RunAsAuthService {
        Authentication changeAuth() {
            return SecurityContextHolder.getSecurityContext().getAuthentication();
        }
    }
}

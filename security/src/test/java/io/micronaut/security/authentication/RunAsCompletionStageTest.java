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
package io.micronaut.security.authentication;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.RunAs;
import io.micronaut.security.annotation.RunAs.Attribute;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import io.micronaut.security.context.SecurityContextHolder;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Property(name = "spec.name", value = "RunAsCompletionStageTest")
@MicronautTest
class RunAsCompletionStageTest {

    @Test
    void runAsIsAvailableForCompletionStageExecution(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        List<ClientAuthentication> authentications = client.retrieve(
            HttpRequest.GET("/runAsCompletionStage").basicAuth("john", "ilikedaenerys"),
            Argument.listOf(ClientAuthentication.class)
        );
        Authentication runAsExpected = Authentication.build(
            "aegon",
            List.of("ROLE_STARK", "ROLE_KING"),
            Map.of("family_name", "Targaryen", "given_name", "John", "roles", List.of("ROLE_STARK", "ROLE_KING"))
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

        authentication = authentications.get(2);
        assertNotNull(authentication);
        assertEquals(expected.getName(), authentication.getName());
        assertEquals(expected.getRoles().stream().toList(), authentication.getRoles().stream().toList());
        assertEquals(expected.getAttributes(), authentication.getAttributes());
    }

    @Requires(property = "spec.name", value = "RunAsCompletionStageTest")
    @Singleton
    static class RunAsProvider<B> implements HttpRequestAuthenticationProvider<B> {
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

    @Requires(property = "spec.name", value = "RunAsCompletionStageTest")
    @Singleton
    static class CompletionStageState {
        private final CompletableFuture<Void> trigger = new CompletableFuture<>();
    }

    @Requires(property = "spec.name", value = "RunAsCompletionStageTest")
    @Controller("/runAsCompletionStage")
    static class RunAsCompletionStageController {
        private final RunAsCompletionStageAuthService runAuthService;
        private final AuthService authService;
        private final CompletionStageState state;

        RunAsCompletionStageController(RunAsCompletionStageAuthService runAuthService,
                                       AuthService authService,
                                       CompletionStageState state) {
            this.runAuthService = runAuthService;
            this.authService = authService;
            this.state = state;
        }

        @Secured("ROLE_STARK")
        @Get
        @SingleResult
        CompletionStage<List<Authentication>> index() {
            CompletionStage<Authentication> runAs = runAuthService.changeAuth()
                .thenApply(ignored -> SecurityContextHolder.getSecurityContext().getAuthentication());
            Authentication pendingAuthentication = SecurityContextHolder.getSecurityContext().getAuthentication();
            state.trigger.complete(null);
            return runAs.thenCombine(authService.auth(), (runAsAuthentication, originalAuthentication) ->
                List.of(runAsAuthentication, pendingAuthentication, originalAuthentication)
            );
        }
    }

    @Requires(property = "spec.name", value = "RunAsCompletionStageTest")
    @Singleton
    static class AuthService {
        CompletionStage<Authentication> auth() {
            return CompletableFuture.completedFuture(SecurityContextHolder.getSecurityContext().getAuthentication());
        }
    }

    @RunAs(
        name = "aegon",
        roles = {"ROLE_KING"},
        attributes = @Attribute(key = "family_name", value = "Targaryen")
    )
    @Requires(property = "spec.name", value = "RunAsCompletionStageTest")
    @Singleton
    static class RunAsCompletionStageAuthService {
        private final CompletionStageState state;

        RunAsCompletionStageAuthService(CompletionStageState state) {
            this.state = state;
        }

        CompletionStage<Authentication> changeAuth() {
            return state.trigger.thenApply(ignored -> Authentication.build("ignored"));
        }
    }
}

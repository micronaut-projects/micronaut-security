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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Property(name = "spec.name", value = "RunAsNameAndRolesTest")
@Property(name = "micronaut.security.token.roles-name", value = "authorities")
@MicronautTest
class RunAsNameAndRolesTest {

    @Test
    void runAsNameSetsTheAuthenticationName(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        List<ClientAuthentication> authentications = client.retrieve(
            HttpRequest.GET("/runAs/name").basicAuth("john", "ilikedaenerys"),
            Argument.listOf(ClientAuthentication.class)
        );

        Authentication authentication = authentications.get(0);
        assertNotNull(authentication);
        assertEquals("aegon", authentication.getName());
        assertEquals(List.of("ROLE_STARK"), authentication.getRoles().stream().toList());
        assertEquals(
            Map.of("family_name", "Snow", "given_name", "John", "roles", List.of("ROLE_STARK")),
            authentication.getAttributes()
        );

        Authentication originalAuthentication = authentications.get(1);
        assertNotNull(originalAuthentication);
        assertEquals("john", originalAuthentication.getName());
        assertEquals(List.of("ROLE_STARK"), originalAuthentication.getRoles().stream().toList());
    }

    @Test
    void runAsNameAndRolesSetAuthenticationNameAndRoles(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        List<ClientAuthentication> authentications = client.retrieve(
            HttpRequest.GET("/runAs/roles").basicAuth("john", "ilikedaenerys"),
            Argument.listOf(ClientAuthentication.class)
        );

        Authentication authentication = authentications.get(0);
        assertNotNull(authentication);
        assertEquals("aegon", authentication.getName());
        assertEquals(List.of("ROLE_STARK", "ROLE_KING", "ROLE_DRAGON"), authentication.getRoles().stream().toList());
        assertEquals(
            Map.of("family_name", "Snow", "given_name", "John", "roles", List.of("ROLE_STARK", "ROLE_KING", "ROLE_DRAGON")),
            authentication.getAttributes()
        );

        Authentication originalAuthentication = authentications.get(1);
        assertNotNull(originalAuthentication);
        assertEquals("john", originalAuthentication.getName());
        assertEquals(List.of("ROLE_STARK"), originalAuthentication.getRoles().stream().toList());
    }

    @Test
    void runAsBlankNameKeepsTheCurrentUser(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        List<ClientAuthentication> authentications = client.retrieve(
            HttpRequest.GET("/runAs/current-user").basicAuth("john", "ilikedaenerys"),
            Argument.listOf(ClientAuthentication.class)
        );

        Authentication authentication = authentications.get(0);
        assertNotNull(authentication);
        assertEquals("john", authentication.getName());
        assertEquals(List.of("ROLE_STARK", "ROLE_DRAGON"), authentication.getRoles().stream().toList());
        assertEquals(
            Map.of("family_name", "Snow", "given_name", "John", "roles", List.of("ROLE_STARK", "ROLE_DRAGON")),
            authentication.getAttributes()
        );
    }

    @Test
    void runAsValueIsAnAliasForRoles(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        List<ClientAuthentication> authentications = client.retrieve(
            HttpRequest.GET("/runAs/value").basicAuth("john", "ilikedaenerys"),
            Argument.listOf(ClientAuthentication.class)
        );

        Authentication authentication = authentications.get(0);
        assertNotNull(authentication);
        assertEquals("john", authentication.getName());
        assertEquals(List.of("ROLE_STARK", "ROLE_LANNISTER"), authentication.getRoles().stream().toList());
        assertEquals(
            Map.of("family_name", "Snow", "given_name", "John", "roles", List.of("ROLE_STARK", "ROLE_LANNISTER")),
            authentication.getAttributes()
        );
    }

    @Test
    void runAsCanReplaceRolesAndAttributes(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        List<ClientAuthentication> authentications = client.retrieve(
            HttpRequest.GET("/runAs/replace").basicAuth("john", "ilikedaenerys"),
            Argument.listOf(ClientAuthentication.class)
        );

        Authentication authentication = authentications.get(0);
        assertNotNull(authentication);
        assertEquals("aegon", authentication.getName());
        assertEquals(List.of("ROLE_KING"), authentication.getRoles().stream().toList());
        assertEquals(
            Map.of("family_name", "Targaryen", "roles", List.of("ROLE_KING")),
            authentication.getAttributes()
        );
    }

    @Requires(property = "spec.name", value = "RunAsNameAndRolesTest")
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

    @Requires(property = "spec.name", value = "RunAsNameAndRolesTest")
    @Controller("/runAs")
    static class RunAsController {
        private final RunAsNameService nameService;
        private final RunAsRolesService rolesService;
        private final RunAsCurrentUserService currentUserService;
        private final RunAsValueService valueService;
        private final RunAsReplaceService replaceService;
        private final AuthService authService;

        RunAsController(RunAsNameService nameService,
                        RunAsRolesService rolesService,
                        RunAsCurrentUserService currentUserService,
                        RunAsValueService valueService,
                        RunAsReplaceService replaceService,
                        AuthService authService) {
            this.nameService = nameService;
            this.rolesService = rolesService;
            this.currentUserService = currentUserService;
            this.valueService = valueService;
            this.replaceService = replaceService;
            this.authService = authService;
        }

        @Secured("ROLE_STARK")
        @Get("/name")
        List<Authentication> name() {
            return List.of(nameService.changeAuth(), authService.auth());
        }

        @Secured("ROLE_STARK")
        @Get("/roles")
        List<Authentication> roles() {
            return List.of(rolesService.changeAuth(), authService.auth());
        }

        @Secured("ROLE_STARK")
        @Get("/current-user")
        List<Authentication> currentUser() {
            return List.of(currentUserService.changeAuth(), authService.auth());
        }

        @Secured("ROLE_STARK")
        @Get("/value")
        List<Authentication> value() {
            return List.of(valueService.changeAuth(), authService.auth());
        }

        @Secured("ROLE_STARK")
        @Get("/replace")
        List<Authentication> replace() {
            return List.of(replaceService.changeAuth(), authService.auth());
        }
    }

    @Requires(property = "spec.name", value = "RunAsNameAndRolesTest")
    @Singleton
    static class AuthService {
        Authentication auth() {
            return SecurityContextHolder.getSecurityContext().getAuthentication();
        }
    }

    @RunAs(name = "aegon")
    @Requires(property = "spec.name", value = "RunAsNameAndRolesTest")
    @Singleton
    static class RunAsNameService {
        Authentication changeAuth() {
            return SecurityContextHolder.getSecurityContext().getAuthentication();
        }
    }

    @RunAs(name = "aegon", roles = {"ROLE_KING", "ROLE_DRAGON"})
    @Requires(property = "spec.name", value = "RunAsNameAndRolesTest")
    @Singleton
    static class RunAsRolesService {
        Authentication changeAuth() {
            return SecurityContextHolder.getSecurityContext().getAuthentication();
        }
    }

    @RunAs(roles = "ROLE_DRAGON")
    @Requires(property = "spec.name", value = "RunAsNameAndRolesTest")
    @Singleton
    static class RunAsCurrentUserService {
        Authentication changeAuth() {
            return SecurityContextHolder.getSecurityContext().getAuthentication();
        }
    }

    @RunAs("ROLE_LANNISTER")
    @Requires(property = "spec.name", value = "RunAsNameAndRolesTest")
    @Singleton
    static class RunAsValueService {
        Authentication changeAuth() {
            return SecurityContextHolder.getSecurityContext().getAuthentication();
        }
    }

    @RunAs(
        name = "aegon",
        roles = "ROLE_KING",
        appendRoles = false,
        attributes = @Attribute(key = "family_name", value = "Targaryen"),
        appendAttributes = false
    )
    @Requires(property = "spec.name", value = "RunAsNameAndRolesTest")
    @Singleton
    static class RunAsReplaceService {
        Authentication changeAuth() {
            return SecurityContextHolder.getSecurityContext().getAuthentication();
        }
    }
}

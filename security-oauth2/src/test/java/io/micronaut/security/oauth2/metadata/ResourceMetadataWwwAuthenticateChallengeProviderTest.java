package io.micronaut.security.oauth2.metadata;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.Status;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.runtime.server.EmbeddedServer;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResourceMetadataWwwAuthenticateChallengeProviderTest {

    static Stream<Object[]> wwwAuthenticateCases() {
        return Stream.of(
            new Object[]{"GET", "/", List.of("")},
            new Object[]{"GET", "/foobar", List.of("", "/foobar")},
            new Object[]{"POST", "/foobar", List.of("", "/foobar")}
        );
    }

    @ParameterizedTest
    @MethodSource("wwwAuthenticateCases")
    void wwwAuthenticateResourceMetadata(String method, String path, List<String> allowedSuffixes) {
        Challenge challenge = challenge("ResourceMetadataWwwAuthenticateChallengeProviderTest", method, path);

        Set<String> allowed = allowedSuffixes.stream()
            .map(suffix -> String.format("Bearer resource_metadata=\"%s/.well-known/oauth-protected-resource%s\"", challenge.baseUrl(), suffix))
            .collect(Collectors.toSet());

        assertTrue(allowed.contains(challenge.header()), () -> "Unexpected WWW-Authenticate: " + challenge.header() + ", allowed: " + allowed);
    }

    @Test
    void wwwAuthenticateScopeFromPathSpecificMetadata() {
        Challenge challenge = challenge("ResourceMetadataWwwAuthenticateChallengeProviderScopeTest", "GET", "/foobar");

        assertEquals(
            String.format("Bearer resource_metadata=\"%s/.well-known/oauth-protected-resource/foobar\", scope=\"foo bar\"", challenge.baseUrl()),
            challenge.header()
        );
    }

    static Stream<String> noScopeCases() {
        return Stream.of(
            "ResourceMetadataWwwAuthenticateChallengeProviderNullScopeTest",
            "ResourceMetadataWwwAuthenticateChallengeProviderEmptyScopeTest",
            "ResourceMetadataWwwAuthenticateChallengeProviderBlankScopeTest"
        );
    }

    @ParameterizedTest
    @MethodSource("noScopeCases")
    void wwwAuthenticateOmitsUnavailableScopes(String specName) {
        Challenge challenge = challenge(specName, "GET", "/foobar");

        assertEquals(
            String.format("Bearer resource_metadata=\"%s/.well-known/oauth-protected-resource/foobar\"", challenge.baseUrl()),
            challenge.header()
        );
        assertFalse(challenge.header().contains("scope="));
    }

    private Challenge challenge(String specName, String method, String path) {
        Map<String, Object> configuration = Map.of(
            "spec.name", specName);
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration);
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        try {
            HttpRequest<?> request = switch (method) {
                case "GET" -> HttpRequest.GET(path).accept(MediaType.TEXT_PLAIN);
                case "POST" -> HttpRequest.POST(path, Collections.emptyMap());
                default -> throw new IllegalArgumentException("Unsupported method: " + method);
            };
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.exchange(request));
            String header = ex.getResponse().getHeaders().get("WWW-Authenticate");
            return new Challenge(server.getURL().toString(), header);
        } finally {
            client.close();
            httpClient.close();
            server.close();
        }
    }

    private record Challenge(String baseUrl, String header) {
    }

    @Requires(property = "spec.name", pattern = "ResourceMetadataWwwAuthenticateChallengeProvider.*")
    @Controller("/foobar")
    static class FooBarController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index() {
            return "foobar";
        }

        @Post
        @Status(HttpStatus.ACCEPTED)
        void save() {
        }
    }

    static class AbstractProtectedResourceMetadataProviderMock implements ProtectedResourceMetadataProvider<HttpRequest<?>> {
        private final HttpHostResolver httpHostResolver;

        AbstractProtectedResourceMetadataProviderMock(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver;
        }

        @Override
        @NonNull
        public ProtectedResourceMetadata get(@NonNull HttpRequest<?> request) {
            return metadata(null, request, null);
        }

        @NonNull
        protected ProtectedResourceMetadata metadata(@Nullable String path,
                                                    @NonNull HttpRequest<?> request,
                                                    @Nullable List<String> scopesSupported) {
            String resource = httpHostResolver.resolve(request) + (path == null ? "" : path);
            return ProtectedResourceMetadata.builder()
                .resource(resource)
                .scopesSupported(scopesSupported)
                .build();
        }
    }

    @Requires(property = "spec.name", value = "ResourceMetadataWwwAuthenticateChallengeProviderScopeTest")
    @Replaces(ProtectedResourceMetadataProvider.class)
    @Singleton
    static class ScopeProtectedResourceMetadataProviderMock extends AbstractProtectedResourceMetadataProviderMock {
        ScopeProtectedResourceMetadataProviderMock(HttpHostResolver httpHostResolver) {
            super(httpHostResolver);
        }

        @Override
        @NonNull
        public ProtectedResourceMetadata get(@NonNull String path, @NonNull HttpRequest<?> request) {
            assertEquals("/foobar", path);
            return metadata(path, request, List.of(" foo ", "bar"));
        }
    }

    @Requires(property = "spec.name", value = "ResourceMetadataWwwAuthenticateChallengeProviderNullScopeTest")
    @Replaces(ProtectedResourceMetadataProvider.class)
    @Singleton
    static class NullScopeProtectedResourceMetadataProviderMock extends AbstractProtectedResourceMetadataProviderMock {
        NullScopeProtectedResourceMetadataProviderMock(HttpHostResolver httpHostResolver) {
            super(httpHostResolver);
        }

        @Override
        @NonNull
        public ProtectedResourceMetadata get(@NonNull String path, @NonNull HttpRequest<?> request) {
            return metadata(path, request, null);
        }
    }

    @Requires(property = "spec.name", value = "ResourceMetadataWwwAuthenticateChallengeProviderEmptyScopeTest")
    @Replaces(ProtectedResourceMetadataProvider.class)
    @Singleton
    static class EmptyScopeProtectedResourceMetadataProviderMock extends AbstractProtectedResourceMetadataProviderMock {
        EmptyScopeProtectedResourceMetadataProviderMock(HttpHostResolver httpHostResolver) {
            super(httpHostResolver);
        }

        @Override
        @NonNull
        public ProtectedResourceMetadata get(@NonNull String path, @NonNull HttpRequest<?> request) {
            return metadata(path, request, List.of());
        }
    }

    @Requires(property = "spec.name", value = "ResourceMetadataWwwAuthenticateChallengeProviderBlankScopeTest")
    @Replaces(ProtectedResourceMetadataProvider.class)
    @Singleton
    static class BlankScopeProtectedResourceMetadataProviderMock extends AbstractProtectedResourceMetadataProviderMock {
        BlankScopeProtectedResourceMetadataProviderMock(HttpHostResolver httpHostResolver) {
            super(httpHostResolver);
        }

        @Override
        @NonNull
        public ProtectedResourceMetadata get(@NonNull String path, @NonNull HttpRequest<?> request) {
            return metadata(path, request, List.of(" ", "\t", ""));
        }
    }

}

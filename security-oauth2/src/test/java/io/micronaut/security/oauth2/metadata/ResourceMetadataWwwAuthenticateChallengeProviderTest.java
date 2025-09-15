package io.micronaut.security.oauth2.metadata;

import io.micronaut.context.ApplicationContext;
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
import io.micronaut.runtime.server.EmbeddedServer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

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
        Map<String, Object> configuration = Map.of(
            "spec.name", "ResourceMetadataWwwAuthenticateChallengeProviderTest");
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

            String base = server.getURL().toString();
            Set<String> allowed = allowedSuffixes.stream()
                .map(suffix -> String.format("Bearer resource_metadata=\"%s/.well-known/oauth-protected-resource%s\"", base, suffix))
                .collect(java.util.stream.Collectors.toSet());

            assertTrue(allowed.contains(header), () -> "Unexpected WWW-Authenticate: " + header + ", allowed: " + allowed);
        } finally {
            client.close();
            httpClient.close();
            server.close();
        }
    }

    @Requires(property = "spec.name", value = "ResourceMetadataWwwAuthenticateChallengeProviderTest")
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

}

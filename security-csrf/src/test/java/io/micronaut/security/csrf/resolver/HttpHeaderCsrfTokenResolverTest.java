package io.micronaut.security.csrf.resolver;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Property(name = "spec.name", value = "HttpHeaderCsrfTokenResolverTest")
@MicronautTest
class HttpHeaderCsrfTokenResolverTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void csrfTokenCanBeResolvedInAnHttpHeader() {
        BlockingHttpClient client = httpClient.toBlocking();
        String expected = "abcde";
        // uppercase header name
        HttpRequest<?> request = HttpRequest.GET("/csrf/echo").header("X-CSRF-TOKEN", expected);
        String token = assertDoesNotThrow(() -> client.retrieve(request));
        assertEquals(expected, token);

        // lowercase header name
        HttpRequest<?> lowerCaseRequest = HttpRequest.GET("/csrf/echo").header("X-CSRF-TOKEN", expected);
        token = assertDoesNotThrow(() -> client.retrieve(lowerCaseRequest));
        assertEquals(expected, token);

        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(HttpRequest.GET("/csrf/echo")));
        assertEquals(HttpStatus.NOT_FOUND, ex.getStatus());
    }

    @Requires(property = "spec.name", value = "HttpHeaderCsrfTokenResolverTest")
    @Controller("/csrf")
    static class CsrfTokenEchoController {

        private final HttpHeaderCsrfTokenResolver httpHeaderCsrfTokenResolver;

        CsrfTokenEchoController(HttpHeaderCsrfTokenResolver httpHeaderCsrfTokenResolver) {
            this.httpHeaderCsrfTokenResolver = httpHeaderCsrfTokenResolver;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/echo")
        Optional<String> echo(HttpRequest<?> request) {
            return httpHeaderCsrfTokenResolver.resolveToken(request);
        }
    }
}
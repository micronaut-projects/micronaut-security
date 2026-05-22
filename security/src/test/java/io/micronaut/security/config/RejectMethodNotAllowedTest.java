package io.micronaut.security.config;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = "spec.name", value = "RejectMethodNotAllowedTest")
@Property(name = "micronaut.security.reject-not-found", value = StringUtils.FALSE)
@Property(name = "micronaut.security.intercept-url-map[0].pattern", value = "/methodNotAllowed")
@Property(name = "micronaut.security.intercept-url-map[0].access[0]", value = "isAuthenticated()")
@MicronautTest
class RejectMethodNotAllowedTest {

    @Test
    void itIsPossibleToReturnMethodNotAllowedInsteadOfUnauthorized(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.exchange(HttpRequest.GET("/methodNotAllowed")));
        assertEquals(HttpStatus.METHOD_NOT_ALLOWED, ex.getStatus());
    }

    @Requires(property = "spec.name", value = "RejectMethodNotAllowedTest")
    @Singleton
    static class MockAuthenticationFetcher implements AuthenticationFetcher {
        @Override
        public Publisher<Authentication> fetchAuthentication(Object request) {
            return Publishers.just(Authentication.build("sdelamo"));
        }
    }

    @Requires(property = "spec.name", value = "RejectMethodNotAllowedTest")
    @Controller("/methodNotAllowed")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    static class RejectMethodNotAllowedController {
        @Produces(MediaType.TEXT_PLAIN)
        @Post
        String post() {
            return "POST";
        }
    }
}

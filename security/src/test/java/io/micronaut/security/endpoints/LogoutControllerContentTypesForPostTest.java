package io.micronaut.security.endpoints;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.*;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.micronaut.security.handlers.LogoutHandler;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class LogoutControllerContentTypesForPostTest {
    @Test
    void notSupportedContentTypeReturnsNotFound() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "LogoutControllerContentTypesForPostTest",
                "micronaut.security.endpoints.logout.post-content-types", List.of(MediaType.APPLICATION_FORM_URLENCODED)
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.exchange(HttpRequest.POST("/logout", Collections.emptyMap())));
        assertEquals(HttpStatus.NOT_FOUND, ex.getStatus());
        httpClient.close();
        server.close();
    }

    @Test
    void supportedContentTypeGoesThrough() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "LogoutControllerContentTypesForPostTest",
                "micronaut.security.endpoints.logout.post-content-types", List.of(MediaType.APPLICATION_FORM_URLENCODED)
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/logout", Collections.emptyMap()).contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        assertDoesNotThrow(() -> client.exchange(request));
        httpClient.close();
        server.close();
    }

    @Test
    void defaultContentTypesSupportFormUrlEncoded() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "LogoutControllerContentTypesForPostTest"
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/logout", Collections.emptyMap()).contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        assertDoesNotThrow(() -> client.exchange(request));
        httpClient.close();
        server.close();
    }

    @Test
    void defaultContentTypesSupportJson() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "LogoutControllerContentTypesForPostTest"
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/logout", Collections.emptyMap()).contentType(MediaType.APPLICATION_JSON_TYPE);
        assertDoesNotThrow(() -> client.exchange(request));
        assertDoesNotThrow(() -> client.exchange(HttpRequest.POST("/logout", Collections.emptyMap())));
        httpClient.close();
        server.close();
    }

    @Requires(property = "spec.name", value = "LogoutControllerContentTypesForPostTest")
    @Singleton
    static class CustomAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {
        @Override
        public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
            return Publishers.just(Authentication.build("sherlock"));
        }
    }

    @Requires(property = "spec.name", value = "LogoutControllerContentTypesForPostTest")
    @Singleton
    static class LogoutHandlerMock implements LogoutHandler<HttpRequest<?>, MutableHttpResponse<?>> {

        @Override
        public MutableHttpResponse<?> logout(HttpRequest<?> request) {
            return HttpResponse.ok();
        }
    }
}

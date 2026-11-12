package io.micronaut.security.test.aot.authserver.a;

import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "micronaut.server.port", value = "-1")
@MicronautTest
class HealthTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void healthEndpoint() {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/health"));
        assertEquals(HttpStatus.OK, response.getStatus());
    }
}

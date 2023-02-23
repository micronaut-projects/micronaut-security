package io.micronaut.security.test.aot.authserver;

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

@MicronautTest
class EndpointsTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void openidConfigurationEndpointExposed() {
        BlockingHttpClient client = httpClient.toBlocking();
        URI uri = UriBuilder.of("/us-east-1_4OqDoWVrZ").path(".well-known").path("openid-configuration").build();

        HttpResponse<?> response = client.exchange(HttpRequest.GET(uri));
        assertEquals(HttpStatus.OK, response.getStatus());
    }
    @Test
    void keysEndpointExposed() {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/keys"));
        assertEquals(HttpStatus.OK, response.getStatus());
    }
}

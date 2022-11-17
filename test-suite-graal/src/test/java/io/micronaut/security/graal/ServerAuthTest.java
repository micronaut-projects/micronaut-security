package io.micronaut.security.graal;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import jakarta.inject.Inject;

import static org.junit.jupiter.api.Assertions.assertEquals;

@MicronautTest
class ServerAuthTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void foo() {
        BlockingHttpClient client = httpClient.toBlocking();

        String expected = "{\"name\":\"testName\",\"attributes\":{\"testKey\":\"testValue\"}}";
        String response = client.retrieve(HttpRequest.GET("/serialize"), String.class);
        assertEquals(expected, response);
    }

}

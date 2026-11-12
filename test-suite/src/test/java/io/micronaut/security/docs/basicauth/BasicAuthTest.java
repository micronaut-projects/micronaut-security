package io.micronaut.security.docs.basicauth;

import io.micronaut.http.HttpRequest;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BasicAuthTest {

    @Test
    void basicAuthSetsTheAuthorizationHeaderWithBasicBase64UsernameAndPassword() {
        // tag::basicAuth[]
        HttpRequest<?> request = HttpRequest.GET("/home").basicAuth("sherlock", "password");
        // end::basicAuth[]
        String encoded = Base64.getEncoder().encodeToString("sherlock:password".getBytes(StandardCharsets.UTF_8));
        assertEquals("Basic " + encoded, request.getHeaders().get("Authorization"));
    }
}

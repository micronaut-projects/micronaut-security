package io.micronaut.security.graal;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.endpoints.introspection.IntrospectionResponse;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "spec.name", value = "IntrospectionResponseTest")
@MicronautTest
class IntrospectionResponseTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void introspectionResponse() {
        BlockingHttpClient client = httpClient.toBlocking();
        URI uri = UriBuilder.of("/introspection").path("response").build();
        String json = client.retrieve(HttpRequest.GET(uri), String.class);
        assertEquals("{\"foo\":\"bar\",\"active\":false}", json);
    }

    @Requires(property = "spec.name", value = "IntrospectionResponseTest")
    @Controller("/introspection")
    static class IntrospectionResponseController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/response")
        IntrospectionResponse index() {
            return new IntrospectionResponse(false,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            Collections.singletonMap("foo", "bar"));
        }
    }
}

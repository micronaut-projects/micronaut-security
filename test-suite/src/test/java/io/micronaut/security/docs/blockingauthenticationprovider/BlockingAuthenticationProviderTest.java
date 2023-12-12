package io.micronaut.security.docs.blockingauthenticationprovider;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@Property(name = "spec.name", value = "BlockingAuthenticationProviderTest")
@MicronautTest
class BlockingAuthenticationProviderTest {

    @Test
    void blockingAuthProvider(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        String json = assertDoesNotThrow(() -> client.retrieve(createRequest("user", "password")));
        String expected = """
                {"message":"Hello World"}""";
        assertEquals(expected, json);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(createRequest("user", "wrong")));
        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
    }

    private HttpRequest<?> createRequest(String userName, String password) {
        return HttpRequest.GET("/messages").basicAuth(userName, password);
    }

    @Requires(property = "spec.name", value = "BlockingAuthenticationProviderTest")
    @Controller("/messages")
    static class HelloWorldController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        Map<String, Object> index() {
            return Collections.singletonMap("message", "Hello World");
        }
    }
}

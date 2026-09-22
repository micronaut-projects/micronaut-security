package io.micronaut.security.docs.rejection;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
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
import org.junit.jupiter.api.function.Executable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = "spec.name", value = "RejectionHandlerOverrideTest")
@MicronautTest
class RejectionHandlerOverrideTest {

    @Test
    void theRejectionHandlerCanBeOverridden(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        Executable e = () -> client.exchange(HttpRequest.GET("/rejection-handler"));
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, e);
        assertEquals("Example Header", ex.getResponse().header("X-Reason"));
    }

    @Requires(property = "spec.name", value = "RejectionHandlerOverrideTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/rejection-handler")
    static class SecuredResource {

        @Get
        String foo() {
            return "";
        }
    }
}

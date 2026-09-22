package io.micronaut.security.docs.siteminder;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "spec.name", value = "SiteminderAuthorizationTest")
@MicronautTest
class SiteminderAuthorizationTest {

    @Test
    void customSiteMinderAuthenticationFetcher(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        String username = UUID.randomUUID().toString();
        HttpRequest<?> request = HttpRequest.GET("/sm").header(SiteminderAuthenticationFetcher.SITEMINDER_USER_HEADER, username);
        assertEquals(username, client.retrieve(request));
    }

    @Requires(property = "spec.name", value = "SiteminderAuthorizationTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/sm")
    static class MyController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Authentication authentication) {
            return authentication.getName();
        }
    }
}

package io.micronaut.security.token.jwt.bearer;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.security.Principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = SecurityConfigurationProperties.PREFIX + ".authentication", value = "bearer")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "spec.name", value = "BearerTokenSeparatorTest")
@MicronautTest
class BearerTokenSeparatorTest {

    @Test
    void theBearerPrefixIsComparedIgnoringCase(TokenGenerator tokenGenerator, @Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        String token = tokenGenerator.generateToken(Authentication.build("sergio"), 3600).orElseThrow();

        assertEquals("sergio", client.retrieve(request("Bearer " + token)));
        assertEquals("sergio", client.retrieve(request("bearer " + token)));
    }

    @Test
    void aSignedJwtAfterTwoSpacesIsStillAccepted(TokenGenerator tokenGenerator, @Client("/") HttpClient httpClient) {
        String token = tokenGenerator.generateToken(Authentication.build("sergio"), 3600).orElseThrow();

        // The reader removes one space only; Nimbus JOSE + JWT trims the remaining leading space before parsing.
        assertEquals("sergio", httpClient.toBlocking().retrieve(request("Bearer  " + token)));
    }

    @Test
    void aMissingSeparatorIsRejected(TokenGenerator tokenGenerator, @Client("/") HttpClient httpClient) {
        String token = tokenGenerator.generateToken(Authentication.build("sergio"), 3600).orElseThrow();

        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().retrieve(request("Bearer" + token)));
        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
    }

    private static HttpRequest<?> request(String authorization) {
        return HttpRequest.GET("/user").header(HttpHeaders.AUTHORIZATION, authorization).accept(MediaType.TEXT_PLAIN);
    }

    @Requires(property = "spec.name", value = "BearerTokenSeparatorTest")
    @Controller
    static class UserController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/user")
        String index(Principal principal) {
            return principal.getName();
        }
    }
}

package io.micronaut.security.docs.bearerauth;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.render.BearerAccessRefreshToken;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Property(name = "spec.name", value = "BearerAuthTest")
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@MicronautTest
class BearerAuthTest {

    @Test
    void bearerAuthSetsTheAuthorizationHeaderWithTheBearerToken(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("sherlock", "password");
        HttpResponse<BearerAccessRefreshToken> rsp = client.exchange(HttpRequest.POST("/login", creds), BearerAccessRefreshToken.class);
        assertEquals(HttpStatus.OK, rsp.status());
        assertNotNull(rsp.body());

        // tag::bearerAuth[]
        String accessToken = rsp.body().getAccessToken();
        List<Book> books = client.retrieve(HttpRequest.GET("/api/gateway")
                .bearerAuth(accessToken), Argument.listOf(Book.class));
        // end::bearerAuth[]
        assertEquals(2, books.size());
    }

    @Requires(property = "spec.name", value = "BearerAuthTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/api")
    static class GatewayController {
        @Get("/gateway")
        List<Book> findAll() {
            return List.of(new Book("1491950358", "Building Microservices"),
                    new Book("1680502395", "Release It!"));
        }
    }

    @Requires(property = "spec.name", value = "BearerAuthTest")
    @Singleton
    static class AuthenticationProviderUserPassword<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            return authRequest.getIdentity().equals("sherlock") && authRequest.getSecret().equals("password")
                ? AuthenticationResponse.success("sherlock")
                : AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
        }
    }
}

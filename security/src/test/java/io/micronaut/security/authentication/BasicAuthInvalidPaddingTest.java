package io.micronaut.security.authentication;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.Principal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Java4Shell (CVE-2026-114938): a Basic Authorization header with a vulnerable Base64 tail is unauthorized,
 * not a server error. The behaviour is the same with or without the guard on an unaffected JDK;
 * {@code io.micronaut.security.utils.Base64DecoderUsageTest} protects the wiring.
 */
@Property(name = "spec.name", value = "BasicAuthInvalidPaddingTest")
@MicronautTest
class BasicAuthInvalidPaddingTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @ParameterizedTest
    @ValueSource(ints = {64, 128})
    void basicHeaderWithJava4ShellPayloadIsUnauthorized(int prefixLength) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.GET("/secured")
                .header(HttpHeaders.AUTHORIZATION, "Basic " + "A".repeat(prefixLength) + "=");

        HttpClientResponseException e = assertThrows(HttpClientResponseException.class, () -> client.exchange(request, String.class));
        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
    }

    @Test
    void basicHeaderWithPaddedCredentialsIsAuthorized() {
        BlockingHttpClient client = httpClient.toBlocking();

        // dXNlcjpwYXNzd29yZA== is user:password
        String body = client.retrieve(HttpRequest.GET("/secured").header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNzd29yZA=="));

        assertEquals("user", body);
    }

    @Requires(property = "spec.name", value = "BasicAuthInvalidPaddingTest")
    @Singleton
    static class AcceptAnyCredentialsProvider<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        public @NonNull AuthenticationResponse authenticate(@Nullable HttpRequest<B> requestContext,
                                                            @NonNull AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success(authRequest.getIdentity());
        }
    }

    @Requires(property = "spec.name", value = "BasicAuthInvalidPaddingTest")
    @Controller("/secured")
    static class SecuredController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        String index(Principal principal) {
            return principal.getName();
        }
    }
}

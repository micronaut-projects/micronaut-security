package io.micronaut.security.docs.securedexpressions;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = "spec.name", value = "docexpressions")
@Property(name = "micronaut.http.client.read-timeout", value = "3600s")
@MicronautTest
class SecuredExpressionsTest {
    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void authenticatedByEmail() {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/authenticated/email").basicAuth("sherlock", "password"));
        assertEquals(HttpStatus.OK, response.status());

        Executable e = () -> client.exchange(HttpRequest.GET("/authenticated/email").basicAuth("moriarty", "password"));
        HttpClientResponseException thrown = assertThrows(HttpClientResponseException.class, e);
        assertEquals(HttpStatus.FORBIDDEN, thrown.getStatus());

        e = () -> client.exchange(HttpRequest.GET("/authenticated/email").basicAuth("watson", "password"));
        thrown = assertThrows(HttpClientResponseException.class, e);
        assertEquals(HttpStatus.UNAUTHORIZED, thrown.getStatus());
    }

    @Requires(property = "spec.name", value = "docexpressions")
    @Singleton
    static class AuthenticationProviderUserPassword  extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(Arrays.asList(
                new SuccessAuthenticationScenario("sherlock", Collections.singletonList("ROLE_ADMIN"), Map.of("email", "sherlock@micronaut.example")),
                new SuccessAuthenticationScenario("moriarty", Collections.singletonList("ROLE_ADMIN"), Map.of("email", "moriarty@micronaut.example"))
            ));
        }
    }
}

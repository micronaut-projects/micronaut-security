package io.micronaut.security.docs.sensitiveendpointrule;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
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

import java.util.Collections;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "micronaut.security.oauth2.enabled", value = StringUtils.FALSE)
@Property(name = "endpoints.beans.enabled", value = StringUtils.TRUE)
@Property(name = "endpoints.beans.sensitive", value = StringUtils.TRUE)
@Property(name = "spec.name", value = "SensitiveEndpointRuleReplacementTest")
@MicronautTest
public class SensitiveEndpointRuleReplacementTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void testAccessingASensitiveEndpointWithAuthenticationAndASensitiveEndpointRuleReplacementWorks() {
        BlockingHttpClient client = httpClient.toBlocking();
        Executable e = () -> client.exchange(HttpRequest.GET("/beans"));
        HttpClientResponseException thrown = assertThrows(HttpClientResponseException.class, e);
        assertEquals(HttpStatus.UNAUTHORIZED, thrown.getStatus());
        e = () -> client.exchange(HttpRequest.GET("/beans").basicAuth("user", "password"));
        assertDoesNotThrow(e);
    }

    @Singleton
    @Requires(property = "spec.name", value = "SensitiveEndpointRuleReplacementTest")
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(Collections.singletonList(new SuccessAuthenticationScenario("user")));
        }
    }
}

package io.micronaut.security.docs.managementendpoints;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.core.util.StringUtils;
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
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@Property(name = "endpoints.health.sensitive", value = StringUtils.FALSE)
@Property(name = "endpoints.health.enabled", value = StringUtils.TRUE)
@Property(name = "endpoints.loggers.sensitive", value = StringUtils.TRUE)
@Property(name = "endpoints.loggers.enabled", value = StringUtils.TRUE)
@Property(name = "micronaut.security.oauth2.enabled", value = StringUtils.FALSE)
@Property(name = "spec.name", value = "LoggersTest")
@MicronautTest
class LoggersTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void healthEndpointIsNotSecured() {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/health"));
        assertEquals(HttpStatus.OK, response.status());
    }

    @Test
    void loggersEndpointIsSecured() {
        BlockingHttpClient client = httpClient.toBlocking();
        Executable e = () -> client.exchange(HttpRequest.GET("/loggers"));
        HttpClientResponseException thrown = assertThrows(HttpClientResponseException.class, e);
        assertEquals(HttpStatus.UNAUTHORIZED, thrown.getStatus());
    }

    @Disabled
    @Test
    void loggersEndpointIsAccessibleForUsersWithRoleROLE_SYSTEM() {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.GET("/loggers").basicAuth("system", "password");
        HttpResponse<Map> response = client.exchange(request, Argument.of(Map.class));
        assertEquals(HttpStatus.OK, response.status());
        Map m = response.body();
        assertTrue(m.containsKey("levels"));
        assertTrue(m.containsKey("loggers"));
    }

    @Test
    void loggersEndpointIsNotAccessibleForUsersWithoutRoleROLE_SYSTEM() {
        BlockingHttpClient client = httpClient.toBlocking();
        Executable e = () -> client.exchange(HttpRequest.GET("/loggers").basicAuth("user", "password"));
        HttpClientResponseException thrown = assertThrows(HttpClientResponseException.class, e);
        assertEquals(HttpStatus.FORBIDDEN, thrown.getStatus());
    }

    @Requires(property = "spec.name", value = "LoggersTest")
    @Singleton
    static class AuthenticationProviderUserPassword  extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(Arrays.asList(
                    new SuccessAuthenticationScenario("user"),
                    new SuccessAuthenticationScenario("system", Collections.singletonList("ROLE_SYSTEM"))
            ));
        }
    }
}

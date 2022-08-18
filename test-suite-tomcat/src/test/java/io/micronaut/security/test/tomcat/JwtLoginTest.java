package io.micronaut.security.test.tomcat;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "spec.name", value = "JwtLoginTest")
@MicronautTest
class JwtLoginTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void loginIsPossibleInTomcatRuntime() {
        BlockingHttpClient client = httpClient.toBlocking();
        assertDoesNotThrow(() -> client.exchange(loginRequest()));
        HttpResponse<Map> response = client.exchange(loginRequest(), Map.class);
        assertTrue(response.getBody().isPresent());
        assertTrue(response.getBody().get().containsKey("access_token"));
    }

    private static HttpRequest<?> loginRequest() {
        return HttpRequest.POST("/login",
            CollectionUtils.mapOf("username", "john", "password", "bogus"));
    }

    @Requires(property = "spec.name", value = "JwtLoginTest")
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        public CustomAuthenticationProvider() {
            super(Collections.singletonList(new SuccessAuthenticationScenario("john")));
        }
    }
}

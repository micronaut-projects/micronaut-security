package io.micronaut.security.docs.authenticationparam;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "AuthenticationParamTest")
@MicronautTest
class AuthenticationParamTest {

    @Test
    void authenticationCanBeUsedAsAControllerParameterToGetTheLoggedInUser(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpResponse<Map<String, Object>> rsp = client.exchange(HttpRequest.GET("/user/myinfo"), Argument.mapOf(String.class, Object.class));
        assertEquals(HttpStatus.OK, rsp.status());
        assertFalse(rsp.body().containsKey("username"));

        rsp = client.exchange(HttpRequest.GET("/user/myinfo").basicAuth("user", "password"), Argument.mapOf(String.class, Object.class));
        assertEquals(HttpStatus.OK, rsp.status());
        assertTrue(rsp.body().containsKey("username"));
        assertEquals("user", rsp.body().get("username"));
        assertEquals(List.of("ROLE_USER"), rsp.body().get("roles"));
    }

    @Requires(property = "spec.name", value = "AuthenticationParamTest")
    @Singleton
    static class AuthenticationProviderUserPassword<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            return authRequest.getIdentity().equals("user") && authRequest.getSecret().equals("password")
                ? AuthenticationResponse.success("user", List.of("ROLE_USER"))
                : AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
        }
    }
}

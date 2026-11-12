package io.micronaut.security.endpoints;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.*;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.MockAuthenticationProvider;
import io.micronaut.security.SuccessAuthenticationScenario;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.handlers.LoginHandler;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class LoginControllerContentTypesForPostTest {
    @ParameterizedTest
    @MethodSource("httpStatusArguments")
    void notSupportedContentTypeReturnsNotFound(HttpStatus httpStatus) {
        HttpStatus expected = httpStatus;
        Map<String, Object> conf = new HashMap<>();
        conf.put("spec.name", "LoginControllerContentTypesForPostTest");
        conf.put("micronaut.security.endpoints.login.post-content-types", List.of(MediaType.APPLICATION_FORM_URLENCODED));
        if (httpStatus != HttpStatus.NOT_FOUND) {
            conf.put("micronaut.security.endpoints.login.unsupported-post-content-type-status", httpStatus.getCode());
        }
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, conf);
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("user", "password");
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.exchange(HttpRequest.POST("/login", creds)));
        assertEquals(expected, ex.getStatus());
        httpClient.close();
        server.close();
    }

    private static Stream<Arguments> httpStatusArguments() {
        return Stream.of(
            Arguments.of(HttpStatus.NOT_FOUND),
            Arguments.of(HttpStatus.UNPROCESSABLE_ENTITY)
        );

    }

    @Test
    void supportedContentTypeGoesThrough() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "LoginControllerContentTypesForPostTest",
                "micronaut.security.endpoints.login.post-content-types", List.of(MediaType.APPLICATION_FORM_URLENCODED)
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("user", "password");
        HttpRequest<?> request = HttpRequest.POST("/login", creds).contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        assertDoesNotThrow(() -> client.exchange(request));
        httpClient.close();
        server.close();
    }

    @Test
    void defaultContentTypesSupportFormUrlEncoded() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "LoginControllerContentTypesForPostTest"
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("user", "password");
        HttpRequest<?> request = HttpRequest.POST("/login", creds).contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        assertDoesNotThrow(() -> client.exchange(request));
        httpClient.close();
        server.close();
    }

    @Test
    void defaultContentTypesSupportJson() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "LoginControllerContentTypesForPostTest"
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("user", "password");
        HttpRequest<?> request = HttpRequest.POST("/login", creds).contentType(MediaType.APPLICATION_JSON_TYPE);
        assertDoesNotThrow(() -> client.exchange(request));
        assertDoesNotThrow(() -> client.exchange(HttpRequest.POST("/login", creds)));
        httpClient.close();
        server.close();
    }

    @Test
    void defaultContentTypesSupportJsonWithCharset() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", "LoginControllerContentTypesForPostTest"
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("user", "password");
        HttpRequest<?> request = HttpRequest.POST("/login", creds).contentType("application/json; charset=UTF-8");
        assertDoesNotThrow(() -> client.exchange(request));
        assertDoesNotThrow(() -> client.exchange(HttpRequest.POST("/login", creds)));
        httpClient.close();
        server.close();
    }

    @Requires(property = "spec.name", value = "LoginControllerContentTypesForPostTest")
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super(List.of(new SuccessAuthenticationScenario("user")));
        }
    }

    @Requires(property = "spec.name", value = "LoginControllerContentTypesForPostTest")
    @Singleton
    static class LoginHandlerMock implements LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> {

        @Override
        public MutableHttpResponse<?> loginSuccess(Authentication authentication, HttpRequest<?> request) {
            return HttpResponse.ok();
        }

        @Override
        public MutableHttpResponse<?> loginRefresh(Authentication authentication, String refreshToken, HttpRequest<?> request) {
            throw new UnsupportedOperationException();
        }

        @Override
        public MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationResponse, HttpRequest<?> request) {
            throw new UnsupportedOperationException();
        }
    }
}

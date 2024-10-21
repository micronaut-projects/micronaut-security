package io.micronaut.security.endpoints;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
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
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.security.token.validator.RefreshTokenValidator;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class OauthControllerContentTypesForPostTest {
    @Test
    void notSupportedContentTypeReturnsNotFound() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "OauthControllerContentTypesForPostTest",
                "micronaut.security.endpoints.oauth.post-content-types", List.of(MediaType.APPLICATION_FORM_URLENCODED)
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.exchange(HttpRequest.POST("/oauth/access_token", Collections.emptyMap())));
        assertEquals(HttpStatus.NOT_FOUND, ex.getStatus());
        httpClient.close();
        server.close();
    }

    @Test
    void supportedContentTypeGoesThrough() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "OauthControllerContentTypesForPostTest",
                "micronaut.security.endpoints.oauth.post-content-types", List.of(MediaType.APPLICATION_FORM_URLENCODED)
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/oauth/access_token", Collections.emptyMap()).contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () ->client.exchange(request));
        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatus());
        httpClient.close();
        server.close();
    }

    @Test
    void defaultContentTypesSupportFormUrlEncoded() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "OauthControllerContentTypesForPostTest"
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/oauth/access_token", Collections.emptyMap()).contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () ->client.exchange(request));
        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatus());
        httpClient.close();
        server.close();
    }

    @Test
    void defaultContentTypesSupportJson() {
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", "OauthControllerContentTypesForPostTest"
        ));
        HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/oauth/access_token", Collections.emptyMap()).contentType(MediaType.APPLICATION_JSON_TYPE);
        HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () ->client.exchange(request));
        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatus());
        httpClient.close();
        server.close();
    }

    @Requires(property = "spec.name", value = "OauthControllerContentTypesForPostTest")
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super(List.of(new SuccessAuthenticationScenario("user")));
        }
    }

    @Requires(property = "spec.name", value = "OauthControllerContentTypesForPostTest")
    @Singleton
    static class RefreshTokenPersistence implements io.micronaut.security.token.refresh.RefreshTokenPersistence {

        @Override
        public void persistToken(RefreshTokenGeneratedEvent event) {

        }

        @Override
        public Publisher<Authentication> getAuthentication(String refreshToken) {
            return Publishers.just(Authentication.build("sherlock"));
        }
    }

    @Requires(property = "spec.name", value = "OauthControllerContentTypesForPostTest")
    @Singleton
    static class CustomRefreshTokenValidator implements  RefreshTokenValidator {

        @Override
        public Optional<String> validate(String refreshToken) {
            return Optional.of(refreshToken);
        }
    }


    @Requires(property = "spec.name", value = "OauthControllerContentTypesForPostTest")
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

package io.micronaut.security.jacksondatabind.beanintrospectionfalse;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@Property(name = "spec.name", value = "LoginControllerValidationTest")
@MicronautTest
class LoginControllerValidationTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    static Stream<Arguments> credentialsProvider() {
        return Stream.of(
                arguments(null, "aabbc12345678"),
                arguments("", "'aabbc12345678'"),
                arguments("'johnny'", null),
                arguments("'johnny'", ""));
    }

    @ParameterizedTest
    @MethodSource("credentialsProvider")
    void loginControllerRespondsBadRequestIfPojoSentToLoginIsInvalid(String username, String password) {
            BlockingHttpClient client = httpClient.toBlocking();

            //given:
            UsernamePasswordCredentials creds = new UsernamePasswordCredentials(username, password);

            //when:
            Argument<String> okArg = Argument.of(String.class);
            Argument<String> errorArgument = Argument.of(String.class);

            //then:
            Executable e = () -> client.exchange(HttpRequest.POST("/login", creds), okArg, errorArgument);
            HttpClientResponseException thrown = assertThrows(HttpClientResponseException.class, e);
            assertEquals(HttpStatus.BAD_REQUEST, thrown.getStatus());

            //when:
            Optional<String> errorOptional = thrown.getResponse().getBody(String.class);

            //then:
            assertTrue(errorOptional.isPresent());

            //when:
            String jsonError = errorOptional.get();

            //then:
            assertTrue(jsonError.contains("must not be blank") || jsonError.contains("must not be null"));
    }


    @Requires(property = "spec.name", value = "LoginControllerValidationTest")
    @Singleton
    static class CustomLoginHandler implements LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> {

        @Override
        public MutableHttpResponse<?> loginSuccess(Authentication authentication, HttpRequest<?> request) {
            return HttpResponse.ok();
        }

        @Override
        public MutableHttpResponse<?> loginRefresh(Authentication authentication, String refreshToken, HttpRequest<?> request) {
            throw new UnsupportedOperationException();
        }

        @Override
        public MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationFailed, HttpRequest<?> request) {
            return HttpResponse.unauthorized();
        }
    }
}

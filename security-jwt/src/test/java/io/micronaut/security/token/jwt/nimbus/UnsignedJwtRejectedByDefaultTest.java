package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.authentication.provider.HttpRequestExecutorAuthenticationProvider;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.jwt.config.JwtConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.JsonWebTokenValidator;
import io.micronaut.security.token.jwt.validator.ReactiveJsonWebTokenValidator;
import io.micronaut.security.token.render.BearerAccessRefreshToken;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With no signature configuration, {@link io.micronaut.security.token.jwt.generator.JwtTokenGenerator} emits unsigned
 * JWTs (alg=none). Because such tokens can be forged by anyone, the validators must reject them by default.
 */
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "spec.name", value = "UnsignedJwtRejectedByDefaultTest")
@MicronautTest
class UnsignedJwtRejectedByDefaultTest {

    @Inject
    BeanContext beanContext;

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Inject
    JsonWebTokenValidator<JWT, HttpRequest<?>> validator;

    @Inject
    ReactiveJsonWebTokenValidator<JWT, HttpRequest<?>> reactiveValidator;

    @Test
    void acceptUnsignedTokensDefaultsToFalseAndNoSignatureConfigurationIsPresent() {
        assertFalse(beanContext.getBean(JwtConfiguration.class).isAcceptUnsignedTokens());
        assertTrue(beanContext.getBeansOfType(SignatureConfiguration.class).isEmpty());
    }

    @Test
    void unsignedTokenIssuedByLoginIsRejected() throws ParseException {
        BlockingHttpClient client = httpClient.toBlocking();
        String accessToken = client.retrieve(HttpRequest.POST("/login", new UsernamePasswordCredentials("sherlock", "password")), BearerAccessRefreshToken.class).getAccessToken();
        assertInstanceOf(PlainJWT.class, JWTParser.parse(accessToken));

        assertUnauthorized(client, "/secured", accessToken);
        assertTrue(validator.validate(accessToken, null).isEmpty());
        assertTrue(Mono.from(reactiveValidator.validate(accessToken, null)).blockOptional().isEmpty());
    }

    @Test
    void forgedUnsignedTokenIsRejected() {
        BlockingHttpClient client = httpClient.toBlocking();
        String forged = new PlainJWT(new JWTClaimsSet.Builder()
                .subject("admin")
                .claim("roles", List.of("ROLE_ADMIN"))
                .build()).serialize();

        assertUnauthorized(client, "/secured", forged);
        assertUnauthorized(client, "/admin", forged);
    }

    private static void assertUnauthorized(BlockingHttpClient client, String path, String token) {
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(HttpRequest.GET(path).bearerAuth(token), String.class));
        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
    }

    @Requires(property = "spec.name", value = "UnsignedJwtRejectedByDefaultTest")
    @Singleton
    static class AuthProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {
        @Override
        public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success("sherlock");
        }
    }

    @Requires(property = "spec.name", value = "UnsignedJwtRejectedByDefaultTest")
    @Controller
    static class SecuredController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get("/secured")
        String secured() {
            return "secured";
        }

        @Secured("ROLE_ADMIN")
        @Get("/admin")
        String admin() {
            return "admin";
        }
    }
}

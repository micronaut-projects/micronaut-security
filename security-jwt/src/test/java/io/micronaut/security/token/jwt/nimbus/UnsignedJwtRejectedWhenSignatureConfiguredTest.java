package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
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
 * Once a signature configuration is present, an unsigned JWT (alg=none) is rejected even if
 * {@code micronaut.security.token.jwt.accept-unsigned-tokens} is true.
 */
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "micronaut.security.token.jwt.accept-unsigned-tokens", value = StringUtils.TRUE)
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "spec.name", value = "UnsignedJwtRejectedWhenSignatureConfiguredTest")
@MicronautTest
class UnsignedJwtRejectedWhenSignatureConfiguredTest {

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
    void acceptUnsignedTokensIsTrueButSignatureConfigurationIsPresent() {
        assertTrue(beanContext.getBean(JwtConfiguration.class).isAcceptUnsignedTokens());
        assertFalse(beanContext.getBeansOfType(SignatureConfiguration.class).isEmpty());
    }

    @Test
    void signedTokenIssuedByLoginIsAccepted() throws ParseException {
        BlockingHttpClient client = httpClient.toBlocking();
        String accessToken = client.retrieve(HttpRequest.POST("/login", new UsernamePasswordCredentials("sherlock", "password")), BearerAccessRefreshToken.class).getAccessToken();
        assertInstanceOf(SignedJWT.class, JWTParser.parse(accessToken));

        assertEquals("secured", client.retrieve(HttpRequest.GET("/secured").bearerAuth(accessToken)));
    }

    @Test
    void forgedUnsignedTokenIsRejectedRegardlessOfAcceptUnsignedTokens() {
        String forged = new PlainJWT(new JWTClaimsSet.Builder()
                .subject("sherlock")
                .claim("roles", List.of("ROLE_ADMIN"))
                .build()).serialize();

        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
                () -> httpClient.toBlocking().exchange(HttpRequest.GET("/secured").bearerAuth(forged), String.class));
        assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
        assertTrue(validator.validate(forged, null).isEmpty());
        assertTrue(Mono.from(reactiveValidator.validate(forged, null)).blockOptional().isEmpty());
    }

    @Requires(property = "spec.name", value = "UnsignedJwtRejectedWhenSignatureConfiguredTest")
    @Singleton
    static class AuthProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {
        @Override
        public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success("sherlock");
        }
    }

    @Requires(property = "spec.name", value = "UnsignedJwtRejectedWhenSignatureConfiguredTest")
    @Controller
    static class SecuredController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get("/secured")
        String secured() {
            return "secured";
        }
    }
}

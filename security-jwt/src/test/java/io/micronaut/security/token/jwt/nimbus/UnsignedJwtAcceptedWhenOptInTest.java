package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
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

import java.security.Principal;
import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With {@code micronaut.security.token.jwt.accept-unsigned-tokens=true} and no signature configuration,
 * unsigned JWTs (alg=none) are accepted. This is an explicit opt-in: such tokens can be forged by anyone.
 */
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "micronaut.security.token.jwt.accept-unsigned-tokens", value = StringUtils.TRUE)
@Property(name = "spec.name", value = "UnsignedJwtAcceptedWhenOptInTest")
@MicronautTest
class UnsignedJwtAcceptedWhenOptInTest {

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
    void acceptUnsignedTokensIsBoundAndNoSignatureConfigurationIsPresent() {
        assertTrue(beanContext.getBean(JwtConfiguration.class).isAcceptUnsignedTokens());
        assertTrue(beanContext.getBeansOfType(SignatureConfiguration.class).isEmpty());
    }

    @Test
    void unsignedTokenIssuedByLoginIsAccepted() throws ParseException {
        BlockingHttpClient client = httpClient.toBlocking();
        String accessToken = client.retrieve(HttpRequest.POST("/login", new UsernamePasswordCredentials("sherlock", "password")), BearerAccessRefreshToken.class).getAccessToken();
        assertInstanceOf(PlainJWT.class, JWTParser.parse(accessToken));

        assertEquals("sherlock", client.retrieve(HttpRequest.GET("/secured").bearerAuth(accessToken)));
        assertTrue(validator.validate(accessToken, null).isPresent());
        assertTrue(Mono.from(reactiveValidator.validate(accessToken, null)).blockOptional().isPresent());
    }

    /**
     * Opting in means anyone can forge a token, which is why the default is {@code false}.
     */
    @Test
    void forgedUnsignedTokenIsAcceptedToo() {
        String forged = new PlainJWT(new JWTClaimsSet.Builder().subject("mallory").build()).serialize();

        assertEquals("mallory", httpClient.toBlocking().retrieve(HttpRequest.GET("/secured").bearerAuth(forged)));
    }

    @Requires(property = "spec.name", value = "UnsignedJwtAcceptedWhenOptInTest")
    @Singleton
    static class AuthProvider<B> implements HttpRequestExecutorAuthenticationProvider<B> {
        @Override
        public AuthenticationResponse authenticate(HttpRequest<B> requestContext, AuthenticationRequest<String, String> authRequest) {
            return AuthenticationResponse.success("sherlock");
        }
    }

    @Requires(property = "spec.name", value = "UnsignedJwtAcceptedWhenOptInTest")
    @Controller
    static class SecuredController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get("/secured")
        String secured(Principal principal) {
            return principal.getName();
        }
    }
}

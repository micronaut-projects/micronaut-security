package io.micronaut.security.endpoints.introspection;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.util.Base64URL;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.core.async.publisher.Publishers;
import org.reactivestreams.Publisher;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.security.token.jwt.generator.SignedRefreshTokenGenerator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "IntrospectionEndpointRefreshTokenLoggingTest")
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "qrD6h8K6S9503Q06Y6Rfk21TErImPYqa")
@Property(name = "micronaut.security.token.jwt.generator.refresh-token.secret", value = "pleaseChangeThisSecretForANewOne")
@MicronautTest
class IntrospectionEndpointRefreshTokenLoggingTest {

    private static final String PAYLOAD = "test-fixture-not-a-secret";

    @Inject
    @Client("/")
    HttpClient httpClient;

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setup() {
        logger = (Logger) LoggerFactory.getLogger(SignedRefreshTokenGenerator.class);
        originalLevel = logger.getLevel();
        logger.setLevel(Level.TRACE);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void cleanup() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(originalLevel);
    }

    @Test
    void introspectingAnEncryptedAccessTokenDoesNotLogTheToken() {
        String jwe = String.join(".",
                base64Url("{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A128GCM\"}"),
                base64Url("encrypted-key-" + PAYLOAD),
                base64Url("iv"),
                base64Url("ciphertext-" + PAYLOAD),
                base64Url("tag"));

        Map<String, Object> body = introspect(jwe);

        assertEquals(Boolean.FALSE, body.get("active"));
        assertNotLogged(jwe);
        assertNotLogged(PAYLOAD);
    }

    @Test
    void introspectingAnAsymmetricallySignedAccessTokenDoesNotLogTheToken() {
        String jws = String.join(".",
                base64Url("{\"alg\":\"RS256\"}"),
                base64Url("{\"sub\":\"sherlock\",\"secret\":\"" + PAYLOAD + "\"}"),
                base64Url("signature"));

        Map<String, Object> body = introspect(jws);

        assertEquals(Boolean.FALSE, body.get("active"));
        assertNotLogged(jws);
        assertNotLogged(PAYLOAD);
    }

    @Test
    void refreshGrantWithAnEncryptedRefreshTokenDoesNotLogTheToken() {
        String jwe = String.join(".",
                base64Url("{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A128GCM\"}"),
                base64Url("encrypted-key-" + PAYLOAD),
                base64Url("iv"),
                base64Url("ciphertext-" + PAYLOAD),
                base64Url("tag"));

        assertRefreshGrantRejected(jwe);
        assertNotLogged(jwe);
        assertNotLogged(PAYLOAD);
    }

    @Test
    void refreshGrantWithAnAsymmetricallySignedRefreshTokenDoesNotLogTheToken() {
        String jws = String.join(".",
                base64Url("{\"alg\":\"RS256\"}"),
                base64Url("{\"sub\":\"sherlock\",\"secret\":\"" + PAYLOAD + "\"}"),
                base64Url("signature"));

        assertRefreshGrantRejected(jws);
        assertNotLogged(jws);
        assertNotLogged(PAYLOAD);
    }

    private void assertRefreshGrantRejected(String refreshToken) {
        HttpRequest<?> request = HttpRequest.POST("/oauth/access_token",
                        Map.of("grant_type", "refresh_token", "refresh_token", refreshToken))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
                () -> httpClient.toBlocking().exchange(request));
        assertEquals(HttpStatus.BAD_REQUEST, e.getStatus());
    }

    private Map<String, Object> introspect(String token) {
        HttpRequest<?> request = HttpRequest.POST("/token_info", new IntrospectionRequest(token, null))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .basicAuth("user", "password");
        HttpResponse<Map<String, Object>> response = httpClient.toBlocking().exchange(request, Argument.mapOf(String.class, Object.class));
        assertEquals(HttpStatus.OK, response.status());
        Map<String, Object> body = response.body();
        assertNotNull(body);
        return body;
    }

    private void assertNotLogged(String value) {
        List<String> messages = appender.list.stream()
                .map(event -> event.getThrowableProxy() == null
                        ? event.getFormattedMessage()
                        : event.getFormattedMessage() + " " + event.getThrowableProxy().getMessage())
                .toList();
        assertTrue(messages.stream().noneMatch(message -> message.contains(value)), () -> value + " was logged: " + messages);
    }

    private static String base64Url(String value) {
        return Base64URL.encode(value.getBytes(StandardCharsets.UTF_8)).toString();
    }

    @Requires(property = "spec.name", value = "IntrospectionEndpointRefreshTokenLoggingTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider<Object, Object, Object> {
        AuthenticationProviderUserPassword() {
            super(List.of(new SuccessAuthenticationScenario("user")));
        }
    }

    @Requires(property = "spec.name", value = "IntrospectionEndpointRefreshTokenLoggingTest")
    @Singleton
    static class NoOpRefreshTokenPersistence implements RefreshTokenPersistence {
        @Override
        public void persistToken(RefreshTokenGeneratedEvent event) {
        }

        @Override
        public Publisher<Authentication> getAuthentication(String refreshToken) {
            return Publishers.empty();
        }
    }
}

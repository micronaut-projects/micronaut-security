package io.micronaut.security.token.jwt.events;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventListener;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.event.TokenValidatedEvent;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.event.AccessTokenGeneratedEvent;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Micronaut core logs every published event at DEBUG through
 * {@code io.micronaut.context.event.ApplicationEventPublisher} using the event's {@code toString()}.
 * The security events that carry a token must therefore never expose it through {@code toString()}.
 */
@Property(name = "spec.name", value = "EventPublisherDebugLoggingTest")
@Property(name = SecurityConfigurationProperties.PREFIX + ".authentication", value = "bearer")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.signatures.secret.generator.secret", value = "test-fixture-not-a-secret-must-be-at-least-256-bits-long")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.generator.refresh-token.secret", value = "refresh-test-fixture-not-a-secret-must-be-at-least-256-bits")
@MicronautTest
class EventPublisherDebugLoggingTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Inject
    TokenEventRecorder recorder;

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setup() {
        logger = (Logger) LoggerFactory.getLogger(ApplicationEventPublisher.class);
        originalLevel = logger.getLevel();
        logger.setLevel(Level.DEBUG);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        recorder.clear();
    }

    @AfterEach
    void cleanup() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(originalLevel);
    }

    @Test
    void tokensAreNotWrittenToTheLogWhenTheEventPublisherLogsAtDebug() {
        BlockingHttpClient client = httpClient.toBlocking();

        BearerAccessRefreshToken rsp = client.retrieve(HttpRequest.POST("/login", new UsernamePasswordCredentials("user", "password")), BearerAccessRefreshToken.class);
        String accessToken = rsp.getAccessToken();
        String signedRefreshToken = rsp.getRefreshToken();
        assertNotNull(accessToken);
        assertNotNull(signedRefreshToken);

        String username = client.retrieve(HttpRequest.GET("/debug-logging").bearerAuth(accessToken));
        assertEquals("user", username);

        // Accepted path: listeners still receive the events and the tokens they carry.
        assertEquals(1, recorder.accessTokenEvents.size());
        assertEquals(accessToken, recorder.accessTokenEvents.get(0).getSource());
        assertEquals(1, recorder.refreshTokenEvents.size());
        String refreshTokenKey = recorder.refreshTokenEvents.get(0).getRefreshToken();
        assertNotNull(refreshTokenKey);
        assertEquals("user", recorder.refreshTokenEvents.get(0).getAuthentication().getName());
        assertEquals(1, recorder.tokenValidatedEvents.size());
        assertEquals(accessToken, recorder.tokenValidatedEvents.get(0).getSource());

        // The event publisher logged each of the events.
        List<String> messages = loggedMessages();
        assertLogged(messages, AccessTokenGeneratedEvent.class.getName());
        assertLogged(messages, RefreshTokenGeneratedEvent.class.getName());
        assertLogged(messages, TokenValidatedEvent.class.getName());

        // Rejected path: the token material never reaches the log.
        assertNotLogged(messages, accessToken);
        assertNotLogged(messages, signedRefreshToken);
        assertNotLogged(messages, refreshTokenKey);
    }

    private List<String> loggedMessages() {
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage).collect(Collectors.toList());
    }

    private static void assertLogged(List<String> messages, String value) {
        assertTrue(messages.stream().anyMatch(message -> message.contains(value)), () -> value + " was not logged");
    }

    private static void assertNotLogged(List<String> messages, String value) {
        assertFalse(messages.stream().anyMatch(message -> message.contains(value)), () -> value + " was logged");
    }

    @Requires(property = "spec.name", value = "EventPublisherDebugLoggingTest")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/debug-logging")
    static class DebugLoggingController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Authentication authentication) {
            return authentication.getName();
        }
    }

    @Requires(property = "spec.name", value = "EventPublisherDebugLoggingTest")
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super(Collections.singletonList(new SuccessAuthenticationScenario("user")));
        }
    }

    @Requires(property = "spec.name", value = "EventPublisherDebugLoggingTest")
    @Singleton
    static class TokenEventRecorder implements RefreshTokenPersistence {

        final List<AccessTokenGeneratedEvent> accessTokenEvents = new CopyOnWriteArrayList<>();
        final List<RefreshTokenGeneratedEvent> refreshTokenEvents = new CopyOnWriteArrayList<>();
        final List<TokenValidatedEvent> tokenValidatedEvents = new CopyOnWriteArrayList<>();

        @Override
        public void persistToken(RefreshTokenGeneratedEvent event) {
            refreshTokenEvents.add(event);
        }

        @Override
        public Publisher<Authentication> getAuthentication(String refreshToken) {
            return Publishers.just(Authentication.build("user"));
        }

        void clear() {
            accessTokenEvents.clear();
            refreshTokenEvents.clear();
            tokenValidatedEvents.clear();
        }
    }

    /**
     * On this branch {@link RefreshTokenPersistence} is itself an event listener, so the access token listener is a separate bean.
     */
    @Requires(property = "spec.name", value = "EventPublisherDebugLoggingTest")
    @Singleton
    static class AccessTokenGeneratedEventRecorder implements ApplicationEventListener<AccessTokenGeneratedEvent> {
        private final TokenEventRecorder recorder;

        AccessTokenGeneratedEventRecorder(TokenEventRecorder recorder) {
            this.recorder = recorder;
        }

        @Override
        public void onApplicationEvent(AccessTokenGeneratedEvent event) {
            recorder.accessTokenEvents.add(event);
        }
    }

    @Requires(property = "spec.name", value = "EventPublisherDebugLoggingTest")
    @Singleton
    static class TokenValidatedEventRecorder implements ApplicationEventListener<TokenValidatedEvent> {
        private final TokenEventRecorder recorder;

        TokenValidatedEventRecorder(TokenEventRecorder recorder) {
            this.recorder = recorder;
        }

        @Override
        public void onApplicationEvent(TokenValidatedEvent event) {
            recorder.tokenValidatedEvents.add(event);
        }
    }
}

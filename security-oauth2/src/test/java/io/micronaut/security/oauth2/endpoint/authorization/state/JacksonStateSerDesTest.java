package io.micronaut.security.oauth2.endpoint.authorization.state;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpRequestWrapper;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.Cookies;
import io.micronaut.http.simple.cookies.SimpleCookies;
import io.micronaut.security.oauth2.endpoint.authorization.response.DefaultOauthAuthorizationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.cookie.CookieStatePersistence;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class JacksonStateSerDesTest {

    private static final String STATE_COOKIE = "OAUTH2_STATE";
    private static final String GUARD_MESSAGE = "Invalid Base64 padding";

    @Inject
    StateSerDes stateSerDes;

    @Inject
    CookieStatePersistence cookieStatePersistence;

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private Logger serdesLogger;
    private Level previousLevel;

    static Stream<String> java4ShellPayloads() {
        // Tail forms from the Calif write-up after one AVX-512 block (64) and the JDK 17 trigger length (128).
        return Stream.of("A".repeat(64), "A".repeat(128))
                .flatMap(prefix -> Stream.of("=", "==", "A=", "A==", "AB=", "===").map(tail -> prefix + tail));
    }

    @BeforeEach
    void captureLogs() {
        serdesLogger = (Logger) LoggerFactory.getLogger(JacksonStateSerDes.class);
        previousLevel = serdesLogger.getLevel();
        serdesLogger.setLevel(Level.DEBUG);
        logs.start();
        serdesLogger.addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        serdesLogger.detachAppender(logs);
        serdesLogger.setLevel(previousLevel);
        logs.stop();
    }

    @Test
    void serdesIsTheJacksonImplementation() {
        assertTrue(stateSerDes instanceof JacksonStateSerDes);
    }

    @ParameterizedTest
    @MethodSource("java4ShellPayloads")
    void stateWithInvalidPaddingIsRejectedByTheGuard(String state) {
        assertNull(stateSerDes.deserialize(state));
        // The JDK decoder fails with a different message: this proves the input never reached it.
        assertTrue(logged(GUARD_MESSAGE), "the Base64Utils guard did not reject the state");
    }

    @Test
    void stateWithCharactersOutsideTheUrlSafeAlphabetDeserializesToNull() {
        assertNull(stateSerDes.deserialize("QU*D"));
    }

    @Test
    void validBase64OfInvalidJsonDeserializesToNull() {
        String notJson = Base64.getUrlEncoder().encodeToString("not json".getBytes(StandardCharsets.UTF_8));

        assertNull(stateSerDes.deserialize(notJson));
    }

    @ParameterizedTest
    @MethodSource("java4ShellPayloads")
    void callbackStateParameterWithInvalidPaddingIsRejectedByTheGuard(String state) {
        HttpRequest<Map<String, Object>> request = HttpRequest.GET("/oauth/callback/example?code=abc&state="
                + URLEncoder.encode(state, StandardCharsets.UTF_8));

        assertNull(new DefaultOauthAuthorizationResponse(request, stateSerDes).getState());
        assertTrue(logged(GUARD_MESSAGE), "the Base64Utils guard did not reject the state parameter");
    }

    @ParameterizedTest
    @MethodSource("java4ShellPayloads")
    void stateCookieWithInvalidPaddingIsRejectedByTheGuard(String state) {
        assertTrue(cookieStatePersistence.retrieveState(requestWithStateCookie(state)).isEmpty());
        assertTrue(logged(GUARD_MESSAGE), "the Base64Utils guard did not reject the state cookie");
    }

    @Test
    void serializedStateRoundTrips() {
        DefaultState state = state();

        assertEquals(state, stateSerDes.deserialize(stateSerDes.serialize(state)));
    }

    @Test
    void serializedStateRoundTripsThroughTheStateCookie() {
        DefaultState state = state();

        assertEquals(state, cookieStatePersistence.retrieveState(requestWithStateCookie(stateSerDes.serialize(state))).orElseThrow());
    }

    private boolean logged(String text) {
        return logs.list.stream().anyMatch(event -> event.getFormattedMessage().contains(text));
    }

    private static DefaultState state() {
        DefaultState state = new DefaultState();
        state.setNonce("4b2f3c1e-9a7d-4c3e-8f1a-2b6d5e7c9a0f");
        state.setRedirectUri(URI.create("https://app.example/oauth/callback/example"));
        return state;
    }

    private static HttpRequest<?> requestWithStateCookie(String value) {
        SimpleCookies cookies = new SimpleCookies(ConversionService.SHARED);
        cookies.put(STATE_COOKIE, Cookie.of(STATE_COOKIE, value));
        return new HttpRequestWrapper<>(HttpRequest.GET("/oauth/callback/example")) {
            @Override
            public Cookies getCookies() {
                return cookies;
            }
        };
    }
}

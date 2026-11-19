package io.micronaut.security.oauth2.endpoint.authorization.state;

import io.micronaut.core.convert.ConversionService;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpRequestWrapper;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.Cookies;
import io.micronaut.http.simple.cookies.SimpleCookies;
import io.micronaut.security.oauth2.endpoint.authorization.response.StateAwareAuthorizationCallback;
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.cookie.CookieStatePersistence;
import io.micronaut.security.oauth2.endpoint.authorization.state.validation.StateValidator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class JacksonStateSerDesTest {

    private static final String STATE_COOKIE = "OAUTH2_STATE";

    @Inject
    StateSerDes stateSerDes;

    @Inject
    CookieStatePersistence cookieStatePersistence;

    @Inject
    StateValidator stateValidator;

    static Stream<String> java4ShellPayloads() {
        // Tail forms from the Calif write-up after one AVX-512 block (64) and the JDK 17 trigger length (128).
        return Stream.of("A".repeat(64), "A".repeat(128))
                .flatMap(prefix -> Stream.of("=", "==", "A=", "A==", "AB=", "===").map(tail -> prefix + tail));
    }

    @Test
    void serdesIsTheJacksonImplementation() {
        assertTrue(stateSerDes instanceof JacksonStateSerDes);
    }

    @ParameterizedTest
    @MethodSource("java4ShellPayloads")
    void stateWithInvalidPaddingDeserializesToNull(String state) {
        assertNull(stateSerDes.deserialize(state));
    }

    @Test
    void stateWithCharactersOutsideTheUrlSafeAlphabetDeserializesToNull() {
        assertNull(stateSerDes.deserialize("QU*D"));
    }

    @ParameterizedTest
    @MethodSource("java4ShellPayloads")
    void callbackStateParameterWithInvalidPaddingIsAnInvalidState(String state) {
        StateAwareAuthorizationCallback callback = new StateAwareAuthorizationCallback(stateSerDes) {
            @Override
            protected String getStateValue() {
                return state;
            }
        };
        HttpRequest<?> request = HttpRequest.GET("/oauth/callback/example");

        assertNull(callback.getState());
        InvalidStateException e = assertThrows(InvalidStateException.class, () -> stateValidator.validate(request, callback.getState()));
        assertEquals("Provided state is null", e.getMessage());
    }

    @ParameterizedTest
    @MethodSource("java4ShellPayloads")
    void stateCookieWithInvalidPaddingIsNotRetrieved(String state) {
        HttpRequest<?> request = requestWithStateCookie(state);

        assertTrue(cookieStatePersistence.retrieveState(request).isEmpty());
    }

    @Test
    void serializedStateRoundTrips() {
        DefaultState state = new DefaultState();
        state.setNonce("4b2f3c1e-9a7d-4c3e-8f1a-2b6d5e7c9a0f");
        state.setRedirectUri(URI.create("https://app.example/oauth/callback/example"));

        String serialized = stateSerDes.serialize(state);

        assertEquals(state, stateSerDes.deserialize(serialized));
    }

    @Test
    void serializedStateRoundTripsThroughTheStateCookie() {
        DefaultState state = new DefaultState();
        state.setNonce("4b2f3c1e-9a7d-4c3e-8f1a-2b6d5e7c9a0f");
        state.setRedirectUri(URI.create("https://app.example/oauth/callback/example"));
        HttpRequest<?> request = requestWithStateCookie(stateSerDes.serialize(state));

        assertEquals(state, cookieStatePersistence.retrieveState(request).orElseThrow());
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

package io.micronaut.security.token.propagation;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HttpHeaderTokenPropagatorTest {

    @Test
    void findTokenComparesThePrefixIgnoringCase() {
        HttpHeaderTokenPropagator propagator = propagator("Bearer");

        assertEquals(Optional.of("XXX"), propagator.findToken(HttpRequest.GET("/").header("Authorization", "Bearer XXX")));
        assertEquals(Optional.of("XXX"), propagator.findToken(HttpRequest.GET("/").header("Authorization", "bearer XXX")));
        assertEquals(Optional.empty(), propagator.findToken(HttpRequest.GET("/").header("Authorization", "Basic XXX")));
        assertEquals(Optional.empty(), propagator.findToken(HttpRequest.GET("/")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Bearer", "Bearer "})
    void findTokenReadsWhatWriteTokenWrote(String prefix) {
        HttpHeaderTokenPropagator propagator = propagator(prefix);
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        propagator.writeToken(request, "XXX");

        assertEquals("Bearer XXX", request.getHeaders().get("Authorization"));
        assertEquals(Optional.of("XXX"), propagator.findToken(request));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void emptyPrefixWritesAndReadsTheTokenAlone(String prefix) {
        HttpHeaderTokenPropagator propagator = propagator(prefix);
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        propagator.writeToken(request, "XXX");

        assertEquals("XXX", request.getHeaders().get("Authorization"));
        assertEquals(Optional.of("XXX"), propagator.findToken(request));
    }

    private static HttpHeaderTokenPropagator propagator(String prefix) {
        HttpHeaderTokenPropagatorConfigurationProperties configuration = new HttpHeaderTokenPropagatorConfigurationProperties();
        configuration.setPrefix(prefix);
        return new HttpHeaderTokenPropagator(configuration);
    }
}

package io.micronaut.security.token.propagation;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import org.junit.jupiter.api.Test;

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

    @Test
    void findTokenReadsWhatWriteTokenWrote() {
        for (String prefix : new String[] {"Bearer", "Bearer "}) {
            HttpHeaderTokenPropagator propagator = propagator(prefix);
            MutableHttpRequest<?> request = HttpRequest.GET("/");

            propagator.writeToken(request, "XXX");

            assertEquals("Bearer XXX", request.getHeaders().get("Authorization"));
            assertEquals(Optional.of("XXX"), propagator.findToken(request));
        }
    }

    @Test
    void emptyPrefixWritesAndReadsTheTokenAlone() {
        for (String prefix : new String[] {"", null}) {
            HttpHeaderTokenPropagator propagator = propagator(prefix);
            MutableHttpRequest<?> request = HttpRequest.GET("/");

            propagator.writeToken(request, "XXX");

            assertEquals("XXX", request.getHeaders().get("Authorization"));
            assertEquals(Optional.of("XXX"), propagator.findToken(request));
        }
    }

    private static HttpHeaderTokenPropagator propagator(String prefix) {
        HttpHeaderTokenPropagatorConfigurationProperties configuration = new HttpHeaderTokenPropagatorConfigurationProperties();
        configuration.setPrefix(prefix);
        return new HttpHeaderTokenPropagator(configuration);
    }
}

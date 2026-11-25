package io.micronaut.security.token.propagation;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HttpHeaderTokenPropagatorTest {

    @ParameterizedTest(name = "prefix [{0}] reads [{1}] as [{2}]")
    @CsvSource(delimiter = '|', value = {
        "Bearer    | Bearer XXX    | XXX",
        "Bearer    | bearer XXX    | XXX",
        "Bearer    | BEARER XXX    | XXX",
        "Bearer    | 'Bearer '     | ''",
        "Bearer    | 'Bearer  XXX' | ' XXX'",
        "Bearer    | BearerXXX     |",
        "Bearer    | Bearer        |",
        "Bearer    | Basic XXX     |",
        "'Bearer ' | Bearer XXX    | XXX",
        "'Bearer ' | bearer XXX    | XXX",
        "'Bearer ' | BearerXXX     |",
        "'Bearer ' | Bearer        |",
    })
    void findTokenRemovesThePrefixAndOneSpace(String prefix, String header, String expected) {
        HttpHeaderTokenPropagator propagator = propagator(prefix);

        assertEquals(Optional.ofNullable(expected), propagator.findToken(HttpRequest.GET("/").header("Authorization", header)));
    }

    @Test
    void findTokenIsEmptyWithoutTheHeader() {
        assertEquals(Optional.empty(), propagator("Bearer").findToken(HttpRequest.GET("/")));
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

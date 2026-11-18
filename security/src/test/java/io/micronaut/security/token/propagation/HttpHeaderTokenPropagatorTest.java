package io.micronaut.security.token.propagation;

import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HttpHeaderTokenPropagatorTest {

    private static final String TOKEN = "xyz";

    private static HttpHeaderTokenPropagator propagator(String prefix) {
        HttpHeaderTokenPropagatorConfigurationProperties configuration = new HttpHeaderTokenPropagatorConfigurationProperties();
        configuration.setPrefix(prefix);
        return new HttpHeaderTokenPropagator(configuration);
    }

    private static MutableHttpRequest<?> requestWithAuthorization(String value) {
        return HttpRequest.GET("/").header(HttpHeaders.AUTHORIZATION, value);
    }

    private static List<String> authorizationHeaders(HttpRequest<?> request) {
        return request.getHeaders().getAll(HttpHeaders.AUTHORIZATION);
    }

    @Test
    void defaultBearerPrefixWritesPrefixedTokenAndReadsItBack() {
        HttpHeaderTokenPropagator propagator = new HttpHeaderTokenPropagator(new HttpHeaderTokenPropagatorConfigurationProperties());
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        propagator.writeToken(request, TOKEN);

        assertEquals(List.of("Bearer xyz"), authorizationHeaders(request));
        assertEquals(Optional.of(TOKEN), propagator.findToken(request));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " "})
    void blankPrefixIsTreatedAsNoPrefix(String prefix) {
        HttpHeaderTokenPropagator propagator = propagator(prefix);
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        propagator.writeToken(request, TOKEN);

        assertEquals(List.of(TOKEN), authorizationHeaders(request));
        assertEquals(Optional.of(TOKEN), propagator.findToken(request));
    }

    @ParameterizedTest
    @ValueSource(strings = {"bearer x", "BEARER x", "Bearer x"})
    void prefixMatchingIsCaseInsensitive(String headerValue) {
        assertEquals(Optional.of("x"), propagator("Bearer").findToken(requestWithAuthorization(headerValue)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Bearerx", "Basic x", "Bearer"})
    void headerValueWithoutPrefixAndSpaceSeparatorHasNoToken(String headerValue) {
        assertEquals(Optional.empty(), propagator("Bearer").findToken(requestWithAuthorization(headerValue)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Bearer ", "Bearer   "})
    void headerValueWithPrefixButBlankTokenHasNoToken(String headerValue) {
        assertEquals(Optional.empty(), propagator("Bearer").findToken(requestWithAuthorization(headerValue)));
    }

    @Test
    void emptyHeaderValueHasNoTokenWhenNoPrefixIsConfigured() {
        assertEquals(Optional.empty(), propagator("").findToken(requestWithAuthorization("")));
    }

    @Test
    void writingOntoRequestWhichAlreadyCarriesHeaderLeavesExactlyOneHeader() {
        HttpHeaderTokenPropagator propagator = propagator("Bearer");
        MutableHttpRequest<?> request = HttpRequest.GET("/").header("authorization", "bearer old");

        propagator.writeToken(request, "new");

        assertEquals(List.of("Bearer new"), authorizationHeaders(request));
        assertEquals(Optional.of("new"), propagator.findToken(request));
    }

    @Test
    void writingReplacesHeaderWhichCarriesAnotherScheme() {
        HttpHeaderTokenPropagator propagator = propagator("Bearer");
        MutableHttpRequest<?> request = requestWithAuthorization("Basic dXNlcjpwYXNz");

        propagator.writeToken(request, TOKEN);

        assertEquals(List.of("Bearer xyz"), authorizationHeaders(request));
    }

    @Test
    void customHeaderNameIsWrittenAndReadInsteadOfAuthorization() {
        HttpHeaderTokenPropagatorConfigurationProperties configuration = new HttpHeaderTokenPropagatorConfigurationProperties();
        configuration.setHeaderName("X-Token");
        HttpHeaderTokenPropagator propagator = new HttpHeaderTokenPropagator(configuration);
        MutableHttpRequest<?> request = requestWithAuthorization("Basic dXNlcjpwYXNz");

        assertEquals(Optional.empty(), propagator.findToken(request));

        propagator.writeToken(request, TOKEN);

        assertEquals(List.of("Bearer xyz"), request.getHeaders().getAll("X-Token"));
        assertEquals(List.of("Basic dXNlcjpwYXNz"), authorizationHeaders(request));
        assertEquals(Optional.of(TOKEN), propagator.findToken(request));
    }

    @Test
    void tokenWithInnerSpacesRoundTrips() {
        HttpHeaderTokenPropagator propagator = propagator("Bearer");
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        propagator.writeToken(request, "a b");

        assertEquals(Optional.of("a b"), propagator.findToken(request));
    }

    @Test
    void prefixWithTrailingSpaceWritesAndReadsSingleSeparator() {
        HttpHeaderTokenPropagator propagator = propagator("Bearer ");
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        propagator.writeToken(request, TOKEN);

        assertEquals(List.of("Bearer xyz"), authorizationHeaders(request));
        assertEquals(Optional.of(TOKEN), propagator.findToken(request));
    }
}

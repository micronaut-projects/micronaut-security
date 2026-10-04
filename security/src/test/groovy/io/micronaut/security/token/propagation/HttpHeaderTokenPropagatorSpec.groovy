package io.micronaut.security.token.propagation

import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpRequest
import spock.lang.Specification

class HttpHeaderTokenPropagatorSpec extends Specification {

    private static HttpHeaderTokenPropagator propagator(String prefix) {
        HttpHeaderTokenPropagatorConfigurationProperties configuration = new HttpHeaderTokenPropagatorConfigurationProperties()
        configuration.prefix = prefix
        new HttpHeaderTokenPropagator(configuration)
    }

    void "default Bearer prefix writes 'Bearer <token>' and reads it back"() {
        given:
        HttpHeaderTokenPropagator propagator = new HttpHeaderTokenPropagator(new HttpHeaderTokenPropagatorConfigurationProperties())
        MutableHttpRequest<?> request = HttpRequest.GET("/")

        when:
        propagator.writeToken(request, "xyz")

        then:
        request.headers.getAll(HttpHeaders.AUTHORIZATION) == ["Bearer xyz"]
        propagator.findToken(request).get() == "xyz"
    }

    void "prefix '#prefix' is treated as no prefix: header value is exactly the token and round-trips"() {
        given:
        HttpHeaderTokenPropagator propagator = propagator(prefix)
        MutableHttpRequest<?> request = HttpRequest.GET("/")

        when:
        propagator.writeToken(request, "xyz")

        then:
        request.headers.getAll(HttpHeaders.AUTHORIZATION) == ["xyz"]
        propagator.findToken(request).get() == "xyz"

        where:
        prefix << ["", " ", null]
    }

    void "prefix matching is case-insensitive and requires a space separator (header value '#value')"() {
        given:
        HttpHeaderTokenPropagator propagator = propagator("Bearer")
        MutableHttpRequest<?> request = HttpRequest.GET("/").header(HttpHeaders.AUTHORIZATION, value)

        expect:
        propagator.findToken(request) == Optional.ofNullable(expected)

        where:
        value        | expected
        "bearer x"   | "x"
        "BEARER x"   | "x"
        "Bearer x"   | "x"
        "Bearerx"    | null
        "Basic x"    | null
        "Bearer"     | null
    }

    void "writing onto a request that already carries an Authorization header leaves exactly one header"() {
        given:
        HttpHeaderTokenPropagator propagator = propagator("Bearer")
        MutableHttpRequest<?> request = HttpRequest.GET("/").header("authorization", "bearer old")

        when:
        propagator.writeToken(request, "new")

        then:
        request.headers.getAll(HttpHeaders.AUTHORIZATION) == ["Bearer new"]
        propagator.findToken(request).get() == "new"
    }

    void "a prefix with a trailing space writes and reads a single separator"() {
        given:
        HttpHeaderTokenPropagator propagator = propagator("Bearer ")
        MutableHttpRequest<?> request = HttpRequest.GET("/")

        when:
        propagator.writeToken(request, "xyz")

        then:
        request.headers.getAll(HttpHeaders.AUTHORIZATION) == ["Bearer xyz"]
        propagator.findToken(request).get() == "xyz"
    }
}

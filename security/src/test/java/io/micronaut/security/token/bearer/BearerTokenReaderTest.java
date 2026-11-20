package io.micronaut.security.token.bearer;

import io.micronaut.http.HttpRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BearerTokenReaderTest {

    private final BearerTokenReader reader = new BearerTokenReader(new BearerTokenConfigurationProperties());

    @ParameterizedTest(name = "[{0}] is read as [{1}]")
    @CsvSource(delimiter = '|', value = {
        "Bearer XXX    | XXX",
        "bearer XXX    | XXX",
        "'Bearer  XXX' | ' XXX'",
        "BearerXXX     |",
        "Bearer        |",
        "Basic XXX     |",
    })
    void findTokenReadsTheAuthorizationHeader(String header, String expected) {
        assertEquals(Optional.ofNullable(expected), reader.findToken(HttpRequest.GET("/").header("authorization", header)));
    }

    @Test
    void findTokenIsEmptyWithoutTheAuthorizationHeader() {
        assertEquals(Optional.empty(), reader.findToken(HttpRequest.GET("/")));
    }
}

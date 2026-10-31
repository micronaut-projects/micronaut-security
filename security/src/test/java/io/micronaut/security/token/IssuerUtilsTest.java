package io.micronaut.security.token;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IssuerUtilsTest {

    @ParameterizedTest
    @CsvSource({
        "https://auth.example.com, https://auth.example.com",
        "https://auth.example.com, https://auth.example.com/",
        "https://auth.example.com/, https://auth.example.com",
        "HTTPS://auth.example.com, https://auth.example.com",
        "https://auth.example.com, HTTPS://auth.example.com",
        "https://auth.example.com/realms/app, https://auth.example.com/realms/app/"
    })
    void equivalentIssuers(String expected, String actual) {
        assertTrue(IssuerUtils.equivalent(expected, actual));
    }

    @ParameterizedTest
    @CsvSource({
        "https://alpha.example.com, example.com",
        "https://alpha.example.com, https://example.com",
        "https://a.b.example.com, https://b.example.com",
        "https://b.example.com, https://a.b.example.com",
        "https://alpha.example.com, https://evilalpha.example.com",
        "https://auth.example.com, http://auth.example.com",
        "https://auth.example.com, auth.example.com",
        "https://auth.example.com, https://auth.example.com//",
        "https://auth.example.com, https://auth.example.com:443",
        "https://auth.example.com, https://auth.example.com@evil.com",
        "https://auth.example.com, https://evil.com@auth.example.com",
        "https://auth.example.com, https://AUTH.example.com",
        "https://auth.example.com, ' https://auth.example.com'",
        "https://auth.example.com, https://",
        "https://auth.example.com/oauth2/default, default",
        "https://auth.example.com/oauth2/default, oauth2/default",
        "https://auth.example.com/oauth2/default, https://auth.example.com/oauth2/default/extra",
        "http://10.0.0.1, 0.0.1",
        "http://10.0.0.1, http://0.0.1",
        "https://auth.example.com/realms/app, https://auth.example.com/realms/APP",
        "https://auth.example.com/realms/app, https://auth.example.com"
    })
    void differentIssuers(String expected, String actual) {
        assertFalse(IssuerUtils.equivalent(expected, actual));
    }

    @ParameterizedTest
    @CsvSource(value = {"NIL, https://auth.example.com", "https://auth.example.com, NIL", "NIL, NIL", "'', ''", "/, /", "'', https://auth.example.com", "/, https://auth.example.com"}, nullValues = "NIL")
    void nullAndEmptyIssuersNeverMatch(String expected, String actual) {
        assertFalse(IssuerUtils.equivalent(expected, actual));
    }
}

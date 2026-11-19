package io.micronaut.security.authentication;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BasicAuthUtilsTest {

    @ParameterizedTest
    @ValueSource(strings = {"=", "==", "===", "A=", "A==", "AB="})
    void credentialsWithPaddingThatDoesNotCompleteTheFinalUnitAreIgnored(String tail) {
        assertTrue(BasicAuthUtils.parseCredentials("Basic " + "A".repeat(64) + tail).isEmpty());
    }

    @Test
    void java4ShellProofOfConceptHeaderIsIgnored() {
        assertTrue(BasicAuthUtils.parseCredentials("Basic " + "A".repeat(128) + "=").isEmpty());
    }

    @Test
    void credentialsWithTwoPaddingCharactersAreParsed() {
        UsernamePasswordCredentials credentials = BasicAuthUtils.parseCredentials("Basic dXNlcjpwYXNzd29yZA==").orElseThrow();
        assertEquals("user", credentials.getUsername());
        assertEquals("password", credentials.getPassword());
    }

    @Test
    void credentialsWithOnePaddingCharacterAreParsed() {
        UsernamePasswordCredentials credentials = BasicAuthUtils.parseCredentials("Basic dXNlcjpwYXNzOndvcmQ=").orElseThrow();
        assertEquals("user", credentials.getUsername());
        assertEquals("pass:word", credentials.getPassword());
    }
}

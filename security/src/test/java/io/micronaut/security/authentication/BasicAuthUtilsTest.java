package io.micronaut.security.authentication;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Behaviour only: parseCredentials swallows the decoding exception, so these tests pass with or without the
 * Base64Utils guard on an unaffected JDK. {@code io.micronaut.security.utils.Base64DecoderUsageTest} protects
 * the wiring, and {@code Base64UtilsTest} proves the guard.
 */
class BasicAuthUtilsTest {

    // The "=" tail after 64 characters is the proof of concept, tested by name below.
    @ParameterizedTest
    @ValueSource(strings = {"==", "===", "A=", "A==", "AB="})
    void credentialsWithJava4ShellTailAreIgnored(String tail) {
        assertTrue(BasicAuthUtils.parseCredentials("Basic " + "A".repeat(64) + tail).isEmpty());
    }

    @Test
    void java4ShellProofOfConceptHeaderIsIgnored() {
        assertTrue(BasicAuthUtils.parseCredentials("Basic " + "A".repeat(64) + "=").isEmpty());
    }

    @Test
    void java4ShellJdk17ProofOfConceptHeaderIsIgnored() {
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

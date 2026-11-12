package io.micronaut.security.graal;

import io.micronaut.security.password.PasswordEncoder;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class PasswordEncoderTest {

    @Inject
    PasswordEncoder passwordEncoder;

    @Test
    void encodesAndMatchesWithArgon2id() {
        String encoded = passwordEncoder.encode("correct horse battery staple");

        assertTrue(encoded.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));
        assertTrue(passwordEncoder.matches("correct horse battery staple", encoded));
        assertFalse(passwordEncoder.matches("Tr0ub4dor&3", encoded));
    }

    @Test
    void matchesAHashCreatedByAnotherImplementation() {
        // Test vector from the Argon2 reference implementation (phc-winner-argon2, src/test.c)
        String encoded = "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc";

        assertTrue(passwordEncoder.matches("password", encoded));
        assertFalse(passwordEncoder.matches("differentpassword", encoded));
    }
}

package io.micronaut.security.csrf.generator;

import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@MicronautTest(startApplication = false)
class CsrfTokenGeneratorTest {

    @Test
    void generatedCsrfTokensAreUnique(CsrfTokenGenerator csrfTokenGenerator) {
        int attempts = 100;
        Set<String> results = new HashSet<>();
        for (int i = 0; i < attempts; i++) {
            results.add(csrfTokenGenerator.generate());
        }
        assertEquals(attempts, results.size());
    }

}
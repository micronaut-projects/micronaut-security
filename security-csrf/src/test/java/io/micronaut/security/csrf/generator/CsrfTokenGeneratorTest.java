package io.micronaut.security.csrf.generator;

import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.simple.SimpleHttpRequest;
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
        HttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.POST, "/password/change", "usenrame=sherlock&password=123456");
        Set<String> results = new HashSet<>();
        for (int i = 0; i < attempts; i++) {
            results.add(csrfTokenGenerator.generateCsrfToken(request));
        }
        assertEquals(attempts, results.size());
    }

}
package io.micronaut.security.csrf.filter;

import io.micronaut.context.annotation.Property;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@Property(name = "micronaut.security.csrf.filter.regex-pattern", value = "^(?!\\/login).*$")
@MicronautTest(startApplication = false)
class CsrfFilterTest {

    @Test
    void csrfFilterUriMatch(CsrfFilter csrfFilter) {
        assertFalse(csrfFilter.shouldTheFilterProcessTheRequestAccordingToTheUriMatch("/login"));
        assertTrue(csrfFilter.shouldTheFilterProcessTheRequestAccordingToTheUriMatch("/todo/list"));
    }
}
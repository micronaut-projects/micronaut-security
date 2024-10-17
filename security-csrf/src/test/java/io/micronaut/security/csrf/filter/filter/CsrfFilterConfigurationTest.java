package io.micronaut.security.csrf.filter.filter;

import io.micronaut.http.HttpMethod;
import io.micronaut.http.MediaType;
import io.micronaut.security.csrf.filter.CsrfFilterConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class CsrfFilterConfigurationTest {

    @Inject
    CsrfFilterConfiguration csrfFilterConfiguration;

    @Test
    void defaultMethods() {
        assertEquals(Set.of(HttpMethod.POST, HttpMethod.DELETE, HttpMethod.PUT, HttpMethod.PATCH), csrfFilterConfiguration.getMethods());
    }

    @Test
    void defaultContentType() {
        assertEquals(Set.of(MediaType.APPLICATION_FORM_URLENCODED_TYPE, MediaType.MULTIPART_FORM_DATA_TYPE), csrfFilterConfiguration.getContentTypes());
    }

    @Test
    void defaultEnabled() {
        assertTrue(csrfFilterConfiguration.isEnabled());
    }
}
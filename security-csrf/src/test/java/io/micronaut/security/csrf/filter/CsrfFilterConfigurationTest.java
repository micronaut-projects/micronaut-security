package io.micronaut.security.csrf.filter;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.order.OrderUtil;
import io.micronaut.core.order.Ordered;
import io.micronaut.core.util.PathMatcher;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.MediaType;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@Property(name = "micronaut.security.csrf.filter.regex-pattern", value = "^(?!\\/login).*$")
@MicronautTest(startApplication = false)
class CsrfFilterConfigurationTest {

    @Inject
    CsrfFilterConfiguration csrfFilterConfiguration;

    @Inject
    CsrfFilter csrfFilter;

    @Inject
    SecurityFilter securityFilter;

    @Test
    void orderOfFilters() {
        List<Ordered> filters = new ArrayList<>(List.of(csrfFilter, securityFilter));
        OrderUtil.sort(filters);
        assertInstanceOf(SecurityFilter.class, filters.get(0));

        filters = new ArrayList<>(List.of(securityFilter, csrfFilter));
        OrderUtil.sort(filters);
        assertInstanceOf(SecurityFilter.class, filters.get(0));
    }

    @Test
    void defaultMethods() {
        assertEquals(Set.of(HttpMethod.POST, HttpMethod.DELETE, HttpMethod.PUT, HttpMethod.PATCH), csrfFilterConfiguration.getMethods());
    }

    @Test
    void defaultContentType() {
        assertEquals(Set.of(MediaType.APPLICATION_FORM_URLENCODED_TYPE, MediaType.MULTIPART_FORM_DATA_TYPE), csrfFilterConfiguration.getContentTypes());
    }

    @Test
    void regexPatternCanBeChanged() {
        String regexPattern = csrfFilterConfiguration.getRegexPattern();
        assertFalse(PathMatcher.REGEX.matches(csrfFilterConfiguration.getRegexPattern(), "/login"));
        assertTrue(PathMatcher.REGEX.matches(csrfFilterConfiguration.getRegexPattern(), "/todo/list"));
        assertEquals("^(?!\\/login).*$", regexPattern);
    }

    @Test
    void defaultEnabled() {
        assertTrue(csrfFilterConfiguration.isEnabled());
    }
}
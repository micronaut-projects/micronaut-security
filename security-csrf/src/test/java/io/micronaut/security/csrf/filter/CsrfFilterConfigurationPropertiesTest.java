package io.micronaut.security.csrf.filter;

import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.MediaType;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@Property(name = "micronaut.security.csrf.filter.regex-pattern", value = "^(?!\\/login).*$")
@Property(name = "micronaut.security.csrf.filter.methods[0]", value = "TRACE")
@Property(name = "micronaut.security.csrf.filter.methods[1]", value = "HEAD")
@Property(name = "micronaut.security.csrf.filter.content-types[0]", value = "application/xml")
@Property(name = "micronaut.security.csrf.filter.content-types[1]", value = "application/graphql")
@MicronautTest(startApplication = false)
class CsrfFilterConfigurationPropertiesTest {
    @Test
    void testFilterConfigurationSetting(CsrfFilterConfiguration configuration) {
        assertEquals("^(?!\\/login).*$",
            configuration.getRegexPattern());
        assertEquals(Set.of(HttpMethod.TRACE, HttpMethod.HEAD),
            configuration.getMethods());
        assertEquals(Set.of(MediaType.APPLICATION_XML_TYPE, MediaType.APPLICATION_GRAPHQL_TYPE),
                configuration.getContentTypes());
    }

    @Test
    void csrfFilterSetEnabled() {
        CsrfFilterConfigurationProperties configuration = new CsrfFilterConfigurationProperties();
        configuration.setEnabled(false);
        assertFalse(configuration.isEnabled());
    }
}

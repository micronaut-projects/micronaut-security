package io.micronaut.security.csrf;

import io.micronaut.security.token.generator.AccessTokenConfigurationProperties;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static io.micronaut.security.testutils.ConfigurationSchemaUtils.assertDefaults;
import static io.micronaut.security.testutils.ConfigurationSchemaUtils.assertProperty;
import static io.micronaut.security.testutils.ConfigurationSchemaUtils.assertSchemaMetadata;
import static io.micronaut.security.testutils.ConfigurationSchemaUtils.map;
import static io.micronaut.security.testutils.ConfigurationSchemaUtils.properties;
import static io.micronaut.security.testutils.ConfigurationSchemaUtils.schema;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class CsrfConfigurationPropertiesSchemaTest {
    private static final String CONFIGURATION_PROPERTIES_TYPE = "io.micronaut.security.csrf.CsrfConfigurationProperties";
    private static final String FILTER_CONFIGURATION_PROPERTIES_TYPE =
        "io.micronaut.security.csrf.filter.CsrfFilterConfigurationProperties";

    @Test
    void generatedConfigurationSchemaContainsDefaultsFromBindableSetters() throws IOException {
        Map<String, Object> schema = schema(CONFIGURATION_PROPERTIES_TYPE);

        assertSchemaMetadata(schema, CONFIGURATION_PROPERTIES_TYPE, CsrfConfiguration.PREFIX, "configuration-properties");

        Map<String, Object> properties = map(schema, "properties");
        assertCsrfProperty(properties, "session-cookie", "boolean", "boolean", CsrfConfigurationProperties.DEFAULT_SESSION_COOKIE);
        assertCsrfProperty(properties, "http-session-name", "string", "java.lang.String",
            CsrfConfigurationProperties.DEFAULT_HTTP_SESSION_NAME);
        assertCsrfProperty(properties, "random-value-size", "integer", "int", CsrfConfigurationProperties.DEFAULT_RANDOM_VALUE_SIZE);
        assertCsrfProperty(properties, "header-name", "string", "java.lang.String", CsrfConfigurationProperties.DEFAULT_HTTP_HEADER_NAME);
        assertCsrfProperty(properties, "field-name", "string", "java.lang.String", CsrfConfigurationProperties.DEFAULT_FIELD_NAME);
        assertCsrfProperty(properties, "enabled", "boolean", "boolean", CsrfConfigurationProperties.DEFAULT_ENABLED);
        assertCsrfProperty(properties, "cookie-secure", "boolean", "java.lang.Boolean", true);
        assertCsrfProperty(properties, "cookie-name", "string", "java.lang.String", CsrfConfigurationProperties.DEFAULT_COOKIE_NAME);
        assertCsrfProperty(properties, "cookie-path", "string", "java.lang.String", "/");
        assertCsrfProperty(properties, "cookie-http-only", "boolean", "java.lang.Boolean", true);
        assertCsrfProperty(properties, "cookie-max-age", "string", "java.time.Duration",
            String.valueOf(AccessTokenConfigurationProperties.DEFAULT_EXPIRATION));
        assertCsrfProperty(properties, "cookie-same-site", "string", "io.micronaut.http.cookie.SameSite", "Strict");

        Map<String, Object> cookieMaxAge = map(properties, "cookie-max-age");
        assertEquals("duration", cookieMaxAge.get("format"));

        Map<String, Object> cookieSameSite = map(properties, "cookie-same-site");
        assertEquals(List.of("Lax", "Strict", "None"), cookieSameSite.get("enum"));

        assertFalse(map(properties, "signature-key").containsKey("default"));
        assertFalse(map(properties, "cookie-domain").containsKey("default"));
    }

    @Test
    void generatedFilterConfigurationSchemaContainsDefaultsFromBindableSetters() throws IOException {
        assertDefaults(FILTER_CONFIGURATION_PROPERTIES_TYPE, Map.of(
            "methods", "POST,PUT,DELETE,PATCH",
            "content-types", "application/x-www-form-urlencoded,multipart/form-data",
            "enabled", true,
            "regex-pattern", "^.*$"
        ));

        Map<String, Object> properties = properties(FILTER_CONFIGURATION_PROPERTIES_TYPE);
        Map<String, Object> methods = map(properties, "methods");
        assertEquals("array", methods.get("type"));
        assertEquals("java.util.Set", methods.get("x-micronaut-javaType"));
        assertEquals(List.of("OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "CUSTOM"),
            map(methods, "items").get("enum"));

        Map<String, Object> contentTypes = map(properties, "content-types");
        assertEquals("array", contentTypes.get("type"));
        assertEquals("java.util.Set", contentTypes.get("x-micronaut-javaType"));
        assertEquals("string", map(contentTypes, "items").get("type"));
    }

    private static void assertCsrfProperty(Map<String, Object> properties,
                                           String name,
                                           String type,
                                           String javaType,
                                           Object defaultValue) {
        assertProperty(properties, name, type, javaType, defaultValue, CONFIGURATION_PROPERTIES_TYPE, CsrfConfiguration.PREFIX);
    }
}

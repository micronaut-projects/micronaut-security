package io.micronaut.security.session;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static io.micronaut.security.testutils.ConfigurationSchemaUtils.assertDefaults;

class SecuritySessionConfigurationPropertiesSchemaTest {
    private static final String TYPE = "io.micronaut.security.session.SecuritySessionConfigurationProperties";

    @Test
    void generatedConfigurationSchemaContainsDefaults() throws IOException {
        assertDefaults(TYPE, Map.of(
            "enabled", true
        ));
    }
}

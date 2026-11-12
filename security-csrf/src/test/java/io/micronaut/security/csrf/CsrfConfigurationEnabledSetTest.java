package io.micronaut.security.csrf;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

class CsrfConfigurationEnabledSetTest {

    @Test
    void csrfSetEnabled() {
        CsrfConfigurationProperties configuration = new CsrfConfigurationProperties();
        configuration.setEnabled(false);
        assertFalse(configuration.isEnabled());
    }
}

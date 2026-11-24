package io.micronaut.security.cspsecurity;

import io.micronaut.context.ApplicationContext;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The CSP module lives in the {@code io.micronaut.security} package tree, so the package requirement
 * of Micronaut Security applies to it, as the CSP guide warns.
 */
class CspWithSecurityDisabledTest {

    @Test
    void disablingMicronautSecurityDisablesTheCspModule() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("micronaut.security.enabled", false))) {
            assertFalse(context.containsBean(ContentSecurityPolicyGenerator.class));
            assertFalse(context.containsBean(ContentSecurityPolicyNonceGenerator.class));
        }
        try (ApplicationContext context = ApplicationContext.run()) {
            assertTrue(context.containsBean(ContentSecurityPolicyGenerator.class));
        }
    }
}

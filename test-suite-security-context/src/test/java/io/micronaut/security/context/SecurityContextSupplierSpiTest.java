package io.micronaut.security.context;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Verifies that a custom {@link SecurityContextSupplier} can be loaded via SPI.
 */
class SecurityContextSupplierSpiTest {

    @Test
    void securityContextSupplierCanBeSetViaSpi() {
        assertInstanceOf(CustomSecurityContext.class, SecurityContextHolder.getSecurityContext());
    }
}

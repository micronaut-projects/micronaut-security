package io.micronaut.security.context;

/**
 * Test {@link SecurityContextSupplier} implementation loaded through SPI.
 */
public class CustomSecurityContextSupplier implements SecurityContextSupplier {
    @Override
    public SecurityContext getSecurityContext() {
        return new CustomSecurityContext();
    }
}

package io.micronaut.security.annotation;

import io.micronaut.core.annotation.Internal;

/**
 * Allows using the {@link jakarta.annotation.security.RolesAllowed} annotation in Micronaut.
 *
 * @author Fredrik Hov
 */
@Internal
public class JakartaRolesAllowedAnnotationMapper extends RolesAllowedAnnotationMapper {
    @Override
    public String getName() {
        return "jakarta.annotation.security.RolesAllowed";
    }
}

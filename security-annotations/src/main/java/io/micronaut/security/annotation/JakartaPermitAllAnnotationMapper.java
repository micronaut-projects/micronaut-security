package io.micronaut.security.annotation;

import io.micronaut.core.annotation.Internal;

/**
 * Allows using the {@link jakarta.annotation.security.PermitAll} annotation in Micronaut.
 *
 * @author Fredrik Hov
 */
@Internal
public class JakartaPermitAllAnnotationMapper extends PermitAllAnnotationMapper {
    @Override
    public String getName() {
        return "jakarta.annotation.security.PermitAll";
    }
}

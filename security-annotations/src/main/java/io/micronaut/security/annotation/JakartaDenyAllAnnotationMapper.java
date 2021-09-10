package io.micronaut.security.annotation;

import io.micronaut.core.annotation.Internal;

/**
 * Allows using the {@link jakarta.annotation.security.DenyAll} annotation in Micronaut.
 *
 * @author Fredrik Hov
 */
@Internal
public class JakartaDenyAllAnnotationMapper extends DenyAllAnnotationMapper {
    @Override
    public String getName() {
        return "jakarta.annotation.security.DenyAll";
    }
}

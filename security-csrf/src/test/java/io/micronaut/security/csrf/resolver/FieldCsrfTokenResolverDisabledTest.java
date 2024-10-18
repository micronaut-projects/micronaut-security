package io.micronaut.security.csrf.resolver;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

@Property(name = "micronaut.security.csrf.token-resolvers.field.enabled", value = StringUtils.FALSE)
@MicronautTest(startApplication = false)
class FieldCsrfTokenResolverDisabledTest {

    @Inject
    BeanContext beanContext;

    @Test
    void testFieldCsrfTokenResolverDisabled() {
        assertFalse(beanContext.containsBean(FieldCsrfTokenResolver.class));
    }

}
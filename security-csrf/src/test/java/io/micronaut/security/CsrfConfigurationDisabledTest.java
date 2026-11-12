package io.micronaut.security;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

@Property(name = "micronaut.security.csrf.enabled", value = StringUtils.FALSE)
@MicronautTest(startApplication = false)
class CsrfConfigurationDisabledTest {

    @Inject
    BeanContext beanContext;

    @Test
    void disabledCsrf() {
        assertFalse(beanContext.containsBean(CsrfConfiguration.class));
    }
}

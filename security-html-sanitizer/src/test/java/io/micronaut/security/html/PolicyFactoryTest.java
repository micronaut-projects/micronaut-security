package io.micronaut.security.html;


import io.micronaut.context.BeanContext;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.owasp.html.PolicyFactory;

import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class PolicyFactoryTest {
    @Inject
    BeanContext beanContext;

    @Test
    void beanOfTypePolicyFactoryExists() {
        assertTrue(beanContext.containsBean(PolicyFactory.class));
    }
}

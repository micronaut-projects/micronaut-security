package io.micronaut.security.reporting;

import io.micronaut.context.BeanContext;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

@MicronautTest(startApplication = false)
class ReportingEndpointsFilterConditionTest {
    @Inject
    BeanContext beanContext;

    @Test
    void filterNotLoadedIfConditionIsNotSatisfied() {
        assertFalse(beanContext.containsBean(ReportingEndpointsFilter.class));
    }
}

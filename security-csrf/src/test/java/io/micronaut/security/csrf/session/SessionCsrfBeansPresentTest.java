package io.micronaut.security.csrf.session;

import io.micronaut.context.BeanContext;
import io.micronaut.inject.BeanDefinition;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class SessionCsrfBeansPresentTest {

    @Inject
    BeanContext beanContext;

    @Test
    void sessionBackedCsrfBeansAreLoadedWhenMicronautSessionIsOnTheClasspath() {
        assertTrue(beanContext.containsBean(SessionCsrfTokenRepository.class));
        assertTrue(beanContext.containsBean(CsrfSessionPopulator.class));
        assertTrue(beanContext.getAllBeanDefinitions().stream()
                .map(BeanDefinition::getName)
                .anyMatch(CsrfSessionPopulator.class.getName()::equals));
    }
}

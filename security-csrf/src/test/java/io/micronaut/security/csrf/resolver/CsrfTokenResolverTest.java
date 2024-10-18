package io.micronaut.security.csrf.resolver;

import io.micronaut.context.BeanContext;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@MicronautTest(startApplication = false)
class CsrfTokenResolverTest {

    @Inject
    BeanContext beanContext;
    @Test
    void csrfTokenResolversOrder() {
        Collection<CsrfTokenResolver> csrfTokenResolverCollection = beanContext.getBeansOfType(CsrfTokenResolver.class);
        List<CsrfTokenResolver> csrfTokenResolverList = new ArrayList<>(csrfTokenResolverCollection);
        assertEquals(2, csrfTokenResolverList.size());
        assertInstanceOf(HttpHeaderCsrfTokenResolver.class, csrfTokenResolverList.get(0));
        assertInstanceOf(FieldCsrfTokenResolver.class, csrfTokenResolverList.get(1));

    }
}
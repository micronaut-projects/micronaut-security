package io.micronaut.security.csrf.resolver;

import io.micronaut.context.BeanContext;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
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
    List<CsrfTokenResolver<HttpRequest<?>>> csrfTokenResolvers;

    @Inject
    List<ReactiveCsrfTokenResolver<HttpRequest<?>>> reactiveCsrfTokenResolvers;
    @Test
    void csrfTokenResolversOrder() {
        assertEquals(1, csrfTokenResolvers.size());
        assertEquals(1, reactiveCsrfTokenResolvers.size());
        List<ReactiveCsrfTokenResolver<HttpRequest<?>>> all = ReactiveCsrfTokenResolver.of(csrfTokenResolvers, reactiveCsrfTokenResolvers);
        assertEquals(2, all.size());
        // It is important for HTTP Header to be the first one. FieldCsrfTokenResolver requires Netty. Moreover, it is more secure to supply the CSRF token via custom HTTP Header instead of a form field as it is more difficult to exploit.
        assertInstanceOf(ReactiveCsrfTokenResolverAdapter.class, all.get(0)); // with HttpHeaderCsrfTokenResolver inside
        assertInstanceOf(FieldCsrfTokenResolver.class, all.get(1));

    }
}
package io.micronaut.security.http;

import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;

class HttpOptionalTest {

    @Test
    void httpIsOptional() {
        ApplicationContext ctx = assertDoesNotThrow(() ->
            ApplicationContext.builder()
                .eagerInitSingletons(true)
                .start()
        );
        //assertFalse(ctx.containsBean(OauthRouteUrlBuilder.class));
        ctx.close();
    }
}

package io.micronaut.security.http;

import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class HttpOptionalTest {

    @Test
    void youCanEagerlyLoadEverySingletonEvenWithoutMicronautHttp() {
        ApplicationContext ctx = assertDoesNotThrow(() ->
            ApplicationContext.builder()
                .eagerInitSingletons(true)
                .start()
        );
        ctx.close();
    }
}

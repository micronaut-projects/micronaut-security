package io.micronaut.security.endpoints.introspection;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class DefaultIntrospectionProcessorRefreshTokenPersistenceInjectionTest {

    private static final String SPEC_NAME = "DefaultIntrospectionProcessorRefreshTokenPersistenceInjectionTest";

    @Test
    void refreshTokenPersistenceBeanIsInjected() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("spec.name", SPEC_NAME))) {
            DefaultIntrospectionProcessor<?> processor = context.getBean(DefaultIntrospectionProcessor.class);

            assertSame(context.getBean(RefreshTokenPersistence.class), processor.refreshTokenPersistence);
        }
    }

    @Test
    void refreshTokenPersistenceIsNullWithoutABean() {
        try (ApplicationContext context = ApplicationContext.run()) {
            DefaultIntrospectionProcessor<?> processor = context.getBean(DefaultIntrospectionProcessor.class);

            assertNull(processor.refreshTokenPersistence);
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class EmptyRefreshTokenPersistence implements RefreshTokenPersistence {
        @Override
        public void persistToken(RefreshTokenGeneratedEvent event) {
        }

        @Override
        public Publisher<Authentication> getAuthentication(String refreshToken) {
            return Mono.empty();
        }
    }
}

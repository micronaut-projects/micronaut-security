/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.annotation;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.context.SecurityContextHolder;
import io.micronaut.security.filters.SecurityFilter;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import reactor.core.Disposable;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CompletionException;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RunWithSecurityAttributeInterceptorTest {

    @Test
    void addsAttributeOnlyDuringSynchronousInvocation() {
        try (ApplicationContext context = ApplicationContext.run()) {
            AttributeService service = context.getBean(AttributeService.class);
            Authentication authentication = Authentication.build("sherlock", List.of("ROLE_USER"), Map.of("existing", "yes"));
            MutableHttpRequest<?> request = authenticatedRequest(authentication);

            String value = withRequest(request, service::attributeValue);

            assertEquals("scoped", value);
            assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));
            assertEquals("yes", authentication.getAttributes().get("existing"));
            assertFalse(authentication.getAttributes().containsKey("feature"));
        }
    }

    @Test
    void proceedsWithoutAuthentication() {
        try (ApplicationContext context = ApplicationContext.run()) {
            AttributeService service = context.getBean(AttributeService.class);
            MutableHttpRequest<?> request = HttpRequest.GET("/attribute");

            String value = withRequest(request, service::attributeValue);

            assertNull(value);
            assertTrue(request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).isEmpty());
        }
    }

    @Test
    void restoresAfterSynchronousException() {
        try (ApplicationContext context = ApplicationContext.run()) {
            AttributeService service = context.getBean(AttributeService.class);
            Authentication authentication = Authentication.build("sherlock");
            MutableHttpRequest<?> request = authenticatedRequest(authentication);

            IllegalStateException thrown = assertThrows(IllegalStateException.class, () ->
                withRequest(request, service::throwing)
            );

            assertEquals("boom", thrown.getMessage());
            assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));
        }
    }

    @Test
    void restoresNestedAttributes() {
        try (ApplicationContext context = ApplicationContext.run()) {
            OuterAttributeService service = context.getBean(OuterAttributeService.class);
            Authentication authentication = Authentication.build("sherlock");
            MutableHttpRequest<?> request = authenticatedRequest(authentication);

            List<String> values = withRequest(request, service::nestedValues);

            assertEquals(List.of("outer", "inner", "outer"), values);
            assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));
        }
    }

    @Test
    void classLevelAnnotationScopesAttributes() {
        try (ApplicationContext context = ApplicationContext.run()) {
            TypeLevelAttributeService service = context.getBean(TypeLevelAttributeService.class);
            Authentication authentication = Authentication.build("sherlock");
            MutableHttpRequest<?> request = authenticatedRequest(authentication);

            String value = withRequest(request, service::attributeValue);

            assertEquals("type", value);
            assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));
        }
    }

    @Test
    void rejectsBlankAttributeName() {
        try (ApplicationContext context = ApplicationContext.run()) {
            BlankNameService service = context.getBean(BlankNameService.class);
            MutableHttpRequest<?> request = authenticatedRequest(Authentication.build("sherlock"));

            IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () ->
                withRequest(request, service::attributeValue)
            );

            assertEquals("@RunWithSecurityAttribute name cannot be blank", thrown.getMessage());
        }
    }

    @Test
    void restoresAfterReactiveCompletionErrorAndCancellation() {
        try (ApplicationContext context = ApplicationContext.run()) {
            ReactiveAttributeService service = context.getBean(ReactiveAttributeService.class);
            Authentication authentication = Authentication.build("sherlock");
            MutableHttpRequest<?> request = authenticatedRequest(authentication);

            String value = withRequest(request, () -> service.attributeValue().block());
            assertEquals("reactive", value);
            assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));

            IllegalStateException thrown = assertThrows(IllegalStateException.class, () ->
                withRequest(request, () -> service.error().block())
            );
            assertEquals("reactive-boom", thrown.getMessage());
            assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));

            ServerRequestContext.with(request, () -> {
                Disposable disposable = service.never().subscribe();
                assertEquals("reactive", service.subscriptionValue);
                disposable.dispose();
            });
            assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));
        }
    }

    @Test
    void restoresAfterCompletionStageCompletionAndError() {
        try (ApplicationContext context = ApplicationContext.run()) {
            CompletionStageAttributeService service = context.getBean(CompletionStageAttributeService.class);
            Authentication authentication = Authentication.build("sherlock");
            MutableHttpRequest<?> request = authenticatedRequest(authentication);

            CompletionStage<String> stage = withRequest(request, service::attributeValue);
            assertEquals("stage", request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class)
                .map(auth -> auth.getAttributes().get("feature"))
                .orElse(null));

            service.future.complete("done");
            assertEquals("done", stage.toCompletableFuture().join());
            assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));

            CompletionStage<String> errorStage = withRequest(request, service::error);
            service.future.completeExceptionally(new IllegalStateException("stage-boom"));
            CompletionException thrown = assertThrows(CompletionException.class, () -> errorStage.toCompletableFuture().join());
            assertEquals("stage-boom", thrown.getCause().getMessage());
            assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));
        }
    }

    private static MutableHttpRequest<?> authenticatedRequest(Authentication authentication) {
        MutableHttpRequest<?> request = HttpRequest.GET("/attribute");
        request.setAttribute(SecurityFilter.AUTHENTICATION, authentication);
        return request;
    }

    private static <T> T withRequest(MutableHttpRequest<?> request, Supplier<T> supplier) {
        return ServerRequestContext.with(request, supplier);
    }

    private static String currentAttributeValue() {
        Authentication authentication = SecurityContextHolder.getSecurityContext().getAuthentication();
        return authentication == null ? null : (String) authentication.getAttributes().get("feature");
    }

    @Singleton
    static class AttributeService {
        @RunWithSecurityAttribute(name = "feature", value = "scoped")
        String attributeValue() {
            return currentAttributeValue();
        }

        @RunWithSecurityAttribute(name = "feature", value = "scoped")
        String throwing() {
            throw new IllegalStateException("boom");
        }
    }

    @Singleton
    static class OuterAttributeService {
        private final InnerAttributeService innerAttributeService;

        OuterAttributeService(InnerAttributeService innerAttributeService) {
            this.innerAttributeService = innerAttributeService;
        }

        @RunWithSecurityAttribute(name = "feature", value = "outer")
        List<String> nestedValues() {
            return List.of(currentAttributeValue(), innerAttributeService.attributeValue(), currentAttributeValue());
        }
    }

    @Singleton
    static class InnerAttributeService {
        @RunWithSecurityAttribute(name = "feature", value = "inner")
        String attributeValue() {
            return currentAttributeValue();
        }
    }

    @Singleton
    @RunWithSecurityAttribute(name = "feature", value = "type")
    static class TypeLevelAttributeService {
        String attributeValue() {
            return currentAttributeValue();
        }
    }

    @Singleton
    static class BlankNameService {
        @RunWithSecurityAttribute(name = "")
        String attributeValue() {
            return currentAttributeValue();
        }
    }

    @Singleton
    static class ReactiveAttributeService {
        private String subscriptionValue;

        @RunWithSecurityAttribute(name = "feature", value = "reactive")
        Mono<String> attributeValue() {
            return Mono.fromSupplier(RunWithSecurityAttributeInterceptorTest::currentAttributeValue);
        }

        @RunWithSecurityAttribute(name = "feature", value = "reactive")
        Mono<String> error() {
            return Mono.error(new IllegalStateException("reactive-boom"));
        }

        @RunWithSecurityAttribute(name = "feature", value = "reactive")
        Mono<String> never() {
            return Mono.<String>never()
                .doOnSubscribe(subscription -> subscriptionValue = currentAttributeValue());
        }
    }

    @Singleton
    static class CompletionStageAttributeService {
        private CompletableFuture<String> future;

        @RunWithSecurityAttribute(name = "feature", value = "stage")
        CompletionStage<String> attributeValue() {
            future = new CompletableFuture<>();
            return future;
        }

        @RunWithSecurityAttribute(name = "feature", value = "stage")
        CompletionStage<String> error() {
            future = new CompletableFuture<>();
            return future;
        }
    }
}

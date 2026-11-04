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
package io.micronaut.security.dev;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.RuntimeBeanDefinition;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.env.PropertySource;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.context.scope.refresh.ConfigurationRefresher;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.rules.SecurityRuleResult;
import io.micronaut.web.router.Router;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Serves requests through the security filter in development mode, with the development-only router, and
 * changes what the filter was built from: the next request is checked by the new rules. Nothing asks the router to
 * rebuild its routes: it does so itself when the recreated filter destroys the previous one.
 */
class SecurityFilterReloadTest {

    private static final String SPEC = "SecurityFilterReloadTest";

    private ApplicationContext context;
    private EmbeddedServer server;
    private HttpClient client;
    private ConfigurationRefresher refresher;

    @AfterEach
    void close() {
        if (client != null) {
            client.close();
        }
        if (context != null) {
            context.close();
        }
    }

    @Test
    void anInterceptUrlMapChangeIsAppliedToTheNextRequest() {
        start(true);
        SecurityFilter filter = context.getBean(SecurityFilter.class);
        assertEquals(HttpStatus.OK, status("/reload/open"));

        edit(Map.of("micronaut.security.intercept-url-map[0].access[0]", "isAuthenticated()"));

        assertNotSame(filter, context.getBean(SecurityFilter.class));
        assertEquals(HttpStatus.UNAUTHORIZED, status("/reload/open"));

        edit(Map.of("micronaut.security.intercept-url-map[0].access[0]", "isAnonymous()"));

        assertEquals(HttpStatus.OK, status("/reload/open"));
    }

    @Test
    void aSecurityRuleRegisteredAtRuntimeIsAppliedToTheNextRequest() {
        start(true);
        SecurityFilter filter = context.getBean(SecurityFilter.class);
        assertEquals(HttpStatus.OK, status("/reload/open"));

        context.registerBeanDefinition(RuntimeBeanDefinition.builder(RejectingRule.class, RejectingRule::new)
            .exposedTypes(SecurityRule.class, RejectingRule.class)
            .build());

        assertNotSame(filter, context.getBean(SecurityFilter.class));
        assertEquals(HttpStatus.UNAUTHORIZED, status("/reload/open"));
    }

    @Test
    void aContextThatDoesNotTrackBeanDependenciesKeepsTheFilter() {
        start(false);
        SecurityFilter filter = context.getBean(SecurityFilter.class);
        assertEquals(HttpStatus.OK, status("/reload/open"));

        edit(Map.of("micronaut.security.intercept-url-map[0].access[0]", "isAuthenticated()"));

        // nothing is recreated: the change is seen after a restart
        assertSame(filter, context.getBean(SecurityFilter.class));
        assertEquals(HttpStatus.OK, status("/reload/open"));
    }

    @Test
    void theRouterIsTheDevelopmentOne() {
        start(true);
        assertTrue(context.getBean(Router.class).getClass().getName().endsWith("DevRouter"));
    }

    private void start(boolean trackDependencies) {
        context = ApplicationContext.builder()
            .properties(Map.of(
                "spec.name", SPEC,
                "micronaut.dev.enabled", true,
                "micronaut.security.reject-not-found", false,
                "micronaut.security.intercept-url-map[0].pattern", "/reload/**",
                "micronaut.security.intercept-url-map[0].access[0]", "isAnonymous()"
            ))
            .beanDependencyTrackingEnabled(trackDependencies)
            .start();
        // created first: it compares the next refresh against the configuration as it is now
        refresher = context.getBean(ConfigurationRefresher.class);
        server = context.getBean(EmbeddedServer.class).start();
        client = context.createBean(HttpClient.class, server.getURL());
    }

    private void edit(Map<String, Object> properties) {
        context.getEnvironment().addPropertySource(PropertySource.of("edit-" + System.nanoTime(), properties, Integer.MAX_VALUE));
        refresher.refresh();
    }

    private HttpStatus status(String path) {
        try {
            return client.toBlocking().exchange(HttpRequest.GET(path), String.class).getStatus();
        } catch (HttpClientResponseException e) {
            return e.getStatus();
        }
    }

    @Requires(property = "spec.name", value = SPEC)
    @Controller("/reload")
    static class ReloadController {
        @Get("/open")
        String open() {
            return "open";
        }
    }

    static class RejectingRule implements SecurityRule<HttpRequest<?>> {
        @Override
        public Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable Authentication authentication) {
            return Publishers.just(SecurityRuleResult.REJECTED);
        }

        @Override
        public int getOrder() {
            return -1000;
        }
    }
}

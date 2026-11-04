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
import io.micronaut.dev.tck.ReloadHarness;
import io.micronaut.dev.tck.ReloadTck;
import io.micronaut.inject.BeanDefinitionReference;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.filters.SecurityFilter;
import io.netty.util.internal.PlatformDependent;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs a secured application through the development runtime: a change of the intercept-url map is applied
 * to the next request, and a change of an application security rule
 * restarts the application with the new rule. Nothing of security keeps a retired generation reachable.
 */
class SecurityReloadTest {

    private static final String PROPERTIES = """
        micronaut.server.port=-1
        micronaut.security.reject-not-found=false
        micronaut.security.intercept-url-map[0].pattern=/hello/**
        micronaut.security.intercept-url-map[0].access[0]=%s
        """;

    private static final String RULE = """
        package example;

        @jakarta.inject.Singleton
        public class ClosedRule implements io.micronaut.security.rules.SecurityRule<io.micronaut.http.HttpRequest<?>> {
            @Override
            public org.reactivestreams.Publisher<io.micronaut.security.rules.SecurityRuleResult> check(
                    io.micronaut.http.HttpRequest<?> request, io.micronaut.security.authentication.Authentication authentication) {
                return io.micronaut.core.async.publisher.Publishers.just(request.getPath().startsWith("/closed")
                    ? io.micronaut.security.rules.SecurityRuleResult.%s
                    : io.micronaut.security.rules.SecurityRuleResult.UNKNOWN);
            }

            @Override
            public int getOrder() {
                return -1000;
            }
        }
        """;

    private final HttpClient client = HttpClient.newHttpClient();

    @TempDir
    Path project;

    @BeforeAll
    static void initializeNetty() {
        // Netty records why it cannot use Unsafe in a static exception, whose stack trace holds the classes on the
        // stack when Netty is first loaded. Loaded first by the application's main method, that is generation one's
        // Application class, which Netty would keep reachable for the life of the process: loaded here, it is this test
        PlatformDependent.hasUnsafe();
    }

    @Test
    void securityFollowsAReloadAndLeavesNoRetiredGenerationReachable() throws Exception {
        try (ReloadHarness harness = ReloadHarness.inDirectory(project)) {
            harness.property("micronaut.server.port", "-1")
                .property("micronaut.security.reject-not-found", "false")
                .property("micronaut.security.intercept-url-map[0].pattern", "/hello/**")
                .property("micronaut.security.intercept-url-map[0].access[0]", "isAnonymous()");
            harness.source("example.HelloController", """
                package example;

                @io.micronaut.http.annotation.Controller
                public class HelloController {
                    @io.micronaut.http.annotation.Get("/hello")
                    public String hello() {
                        return "hello";
                    }

                    @io.micronaut.http.annotation.Get("/closed")
                    public String closed() {
                        return "closed";
                    }
                }
                """);
            harness.source("example.ClosedRule", RULE.formatted("ALLOWED"));
            harness.start();
            assertReloaderPresent(harness.context());

            assertEquals(200, status(harness, "/hello"));
            assertEquals(200, status(harness, "/closed"));
            ReloadTck.assertFollowsReload(harness, SecurityReloadTest::applicationRule);

            // the intercept-url map changes: the next request is checked against the new map, whether the runtime
            // applies the change in place or restarts for it
            harness.resource("application.properties", PROPERTIES.formatted("isAuthenticated()"));
            harness.reload();

            assertEquals(401, status(harness, "/hello"));
            assertEquals(200, status(harness, "/closed"));

            // an application rule changes: the application restarts with it
            int generation = harness.generation();
            harness.source("example.ClosedRule", RULE.formatted("REJECTED"));
            harness.reload();
            assertTrue(harness.generation() > generation);
            assertReloaderPresent(harness.context());

            assertEquals(401, status(harness, "/hello"));
            assertEquals(401, status(harness, "/closed"));
            ReloadTck.assertFollowsReload(harness, SecurityReloadTest::applicationRule);

            // neither the rules, the filter nor the development-only reloader keep a retired generation reachable
            releaseCoreResidual(harness.context());
            ReloadTck.assertRetiredGenerationsCollected(harness);
        }
    }

    /**
     * A residual of core, not of security: a bean definition of the parent tier keeps, on its static executable methods
     * ({@code $EXEC}), the environment of the last context that loaded it. The development runtime loads the definition of
     * the heartbeat task of discovery-core, which the HTTP client brings, in one generation and not in the next, so the
     * environment of a retired generation stays on {@code $HeartbeatTask$Definition.$EXEC}. Loading it in the current
     * context configures it with the current environment.
     */
    @SuppressWarnings("unchecked")
    private static void releaseCoreResidual(ApplicationContext context) throws ReflectiveOperationException {
        // disabled, the definition is not among the context's references: it is created as the context would create it
        Class<?> type = Class.forName("io.micronaut.health.$HeartbeatTask$Definition", true, ApplicationContext.class.getClassLoader());
        Constructor<?> constructor = type.getDeclaredConstructor();
        constructor.setAccessible(true);
        ((BeanDefinitionReference<Object>) constructor.newInstance()).load(context);
    }

    private int status(ReloadHarness harness, String path) throws IOException, InterruptedException {
        URI uri = harness.context().getBean(EmbeddedServer.class).getURI().resolve(path);
        return client.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    private static void assertReloaderPresent(ApplicationContext context) {
        // the bean that recreates the rules and the filter exists in development mode only
        assertTrue(context.containsBean(type(context, "io.micronaut.security.filters.DevelopmentSecurityReloader")));
    }

    /**
     * @return The application rule the security filter checks requests with
     */
    private static Object applicationRule(ApplicationContext context) {
        try {
            Field rules = SecurityFilter.class.getDeclaredField("securityRules");
            rules.setAccessible(true);
            Collection<?> held = (Collection<?>) rules.get(context.getBean(SecurityFilter.class));
            Class<?> rule = type(context, "example.ClosedRule");
            return held.stream().filter(rule::isInstance).findFirst().orElse(null);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Cannot read the rules of the security filter", e);
        }
    }

    private static Class<?> type(ApplicationContext context, String className) {
        try {
            return Class.forName(className, true, context.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new AssertionError(className + " is not in the application", e);
        }
    }
}
